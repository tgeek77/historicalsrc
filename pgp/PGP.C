/*
	Pretty Good(tm) Privacy - RSA public key cryptography for the masses
	Written by Philip Zimmermann, Phil's Pretty Good(tm) Software.
	Beta test version 1.0 - Last revised 5 Jun 91 by PRZ

	PGP combines the convenience of the Rivest-Shamir-Adleman (RSA)
	public key cryptosystem with the speed of fast conventional
	cryptographic algorithms, fast message digest algorithms, data
	compression, and sophisticated key management.  And PGP performs 
	the RSA functions faster than most other software implementations.  
	PGP is RSA public key cryptography for the masses.

	Uses RSA Data Security, Inc. MD4 Message Digest Algorithm
	for signatures.  Uses the LZHUF algorithm for compression.
	Uses my own algorithm, BassOmatic, for conventional encryption.

	(c) Copyright 1990 by Philip Zimmermann.  All rights reserved.
	The author assumes no liability for damages resulting from the use 
	of this software, even if the damage results from defects in this 
	software.  No warranty is expressed or implied.  

	All the source code I wrote for PGP is available for free under 
	the "Copyleft" General Public License from the Free Software 
	Foundation.  A copy of that license agreement is included in the 
	source release package of PGP.  The source code for the MD4 
	functions and the LZHUF functions were separately placed in the 
	public domain by their respective authors.  See the PGP User's 
	Guide for more complete information about licensing, patent 
	restrictions on the RSA algorithm, trademarks, copyrights, and 
	export controls.  Technical assistance from me is available for 
	an hourly fee.


	PGP generally zeros its used stack and memory areas before exiting.  
	This avoids leaving sensitive information in RAM where other users 
	could find it later.  The RSA library and keygen routines also 
	sanitize their own stack areas.  This stack sanitizing has not been 
	checked out under all the error exit conditions, when routines exit 
	abnormally.  Also, we must find a way to clear the C I/O library 
	file buffers, and the MSDOS disk buffers.  
	
	The code in this source file (pgp.c) was hastily written, and it 
	shows.  It has a lot of redundant code, developed by ad-hoc 
	"accretion" rather than by well-planned design.  It isn't buggy, but 
	it needs to be reorganized to make it cleaner, clearer, and more 
	succinct.  Maybe someday.  Better and more typical examples of my 
	programming style can be seen in the RSA library code in rsalib.c 
	and keygen.c, and in the BassOmatic conventional encryption routines 
	in basslib.c and related files.

	If you modify this code, PLEASE preserve the style of indentation 
	used for {begin...end} blocks.  It drives me bats to have to deal 
	with more than one style in the same program.

*/


#include <stdlib.h>	/* for exit(), malloc(), free(), etc. */
#include <stdio.h>	/* for printf(), tmpfile(), etc.	*/
#include <time.h>	/* for timestamps and performance measurement */
#include <string.h>	/* for strcat(), etc.	*/
#include <io.h>
#include <conio.h>	/* for kbhit() 			*/

#include "md4.h"	/* for MD4 message digest stuff */
#include "rsalib.h"
#include "rsaio.h"
#include "keygen.h"
#include "random.h"
#include "basslib.h"
#include "basslib2.h"

#define KEYFRAGSIZE 8	/* # of bytes in key ID modulus fragment */
#define SIZEOF_TIMESTAMP 4 /* 32-bit timestamp */

/* This macro is for burning sensitive data (byte arrays only) on stack */
#define burn(x) fill0(x,sizeof(x))

/*
**********************************************************************
*/

/* Cipher Type Byte (CTB) definitions follow...*/
#define CTB_DESIGNATOR 0x80
#define is_ctb(c) (((c) & CTB_DESIGNATOR)==CTB_DESIGNATOR)
#define CTB_TYPE_MASK 0x7c
#define CTB_LLEN_MASK 0x03

/* length of length field of packet, in bytes (1, 2, 4, 8 bytes): */
#define ctb_llength(ctb) ((int) 1 << (int) ((ctb) & CTB_LLEN_MASK))

#define is_ctb_type(ctb,type) (((ctb) & CTB_TYPE_MASK)==(4*type))
#define CTB_BYTE(type,llen) (CTB_DESIGNATOR + (4*type) + llen)

#define CTB_PKE_TYPE 1	/* packet encrypted with RSA public key */
#define CTB_SKE_TYPE 2	/* packet signed with RSA secret key */
#define CTB_MD_TYPE 3		/* message digest packet */
#define CTB_CONKEY_TYPE 4	/* conventional key packet */
#define CTB_CERT_SECKEY_TYPE 5  /* secret key certificate */
#define CTB_CERT_PUBKEY_TYPE 6  /* public key certificate */
#define CTB_COMPRESSED_TYPE 8	/* compressed data packet */
#define CTB_CKE_TYPE 9			/* conventional-key-encrypted data */
#define CTB_LITERAL_TYPE 12			/* raw data */

/* Unimplemented CTB packet types follow... */
/* #define CTB_RAW1_TYPE 13		/* raw data, with filename, date, crc32 prefix */
/* #define CTB_PATTERN_TYPE 14	/* unique file prefix autorecognition pattern */
/* #define CTB_EXTENDED_TYPE 15	/* 2-byte CTB, 256 extra CTB types */

#define CTB_PKE CTB_BYTE(CTB_PKE_TYPE,1)
	/* CTB_PKE len16 keyID mpi(RSA(CONKEYPKT)) */
	/*	  1		 2	 SIZE  countbytes()+2 */
#define CTB_SKE CTB_BYTE(CTB_SKE_TYPE,1)
	/* CTB_SKE len16 keyID mpi(RSA(MDPKT)) */
	/*	  1		 2	 SIZE  countbytes()+2 */
#define CTB_MD CTB_BYTE(CTB_MD_TYPE,0)
	/* CTB_MD len8 algorithm MD timestamp */
#define CTB_CONKEY CTB_BYTE(CTB_CONKEY_TYPE,0)
	/* CTB_CONKEY len8 algorithm key */
#define CTB_CERT_SECKEY CTB_BYTE(CTB_CERT_SECKEY_TYPE,1)
	/* CTB_CERT_SECKEY len16 timestamp userID mpi(n) mpi(e) mpi(d) mpi(p) mpi(q) mpi(u) crc16 */
#define CTB_CERT_PUBKEY CTB_BYTE(CTB_CERT_PUBKEY_TYPE,1)
	/* CTB_CERT_PUBKEY len16 timestamp userID mpi(n) mpi(e) crc16 */

/*	Note that a "secret key compromised" certificate is exactly the same 
	as a public key certificate, but with mpi(e)==0. */

#define CTB_CKE CTB_BYTE(CTB_CKE_TYPE,3)
	/*	CTB_CKE ciphertext */

#define CTB_LITERAL CTB_BYTE(CTB_LITERAL_TYPE,3)
	/*	CTB_LITERAL data */

#define CTB_COMPRESSED CTB_BYTE(CTB_COMPRESSED_TYPE,3)
	/*	CTB_COMPRESSED compressedtext */

#define CTB_PATTERN CTB_BYTE(CTB_PATTERN_TYPE,0)
	/*	Unique 40-bit auto-recognition prefix pattern: B8 03 'P' 'R' 'Z' */

/*	Conventional encryption algorithm selector bytes. */
#define DES_ALGORITHM_BYTE	1	/*	use the DES	(unimplemented)	*/
#define BASS_ALGORITHM_BYTE	2	/*	use the BassOmatic		*/

/*	Message digest algorithm selector bytes. */
#define MD4_ALGORITHM_BYTE 1	/* MD4 message digest algorithm */

/*	Data compression algorithm selector bytes. */
#define LZH_ALGORITHM_BYTE 1	/* LZH compression algorithm */

#define is_secret_key(ctb) is_ctb_type(ctb,CTB_CERT_SECKEY_TYPE)

#define MAX_SIGCERT_LENGTH (1+2 + KEYFRAGSIZE + 2+MAX_BYTE_PRECISION)

#define MAX_KEYCERT_LENGTH (1+2+4+256 + 5*(2+MAX_BYTE_PRECISION))


/* Global filenames and system-wide file extensions... */
char CTX_EXTENSION[] = ".ctx";
char PUB_EXTENSION[] = ".pub";
char SEC_EXTENSION[] = ".sec";
char SCRATCH_CTX_FILENAME[] = "_pgptemp.ctx";
char SCRATCH_PTX_FILENAME[] = "_pgptemp.ptx";
char SCRATCH_KEYRING_FILENAME[] = "_tmpring.pub"; /* gets modified */
char PGPPATH[] = "PGPPATH";	/* environmental variable */

/* These files use the environmental variable PGPPATH as a default path: */
char PUBLIC_KEYRING_FILENAME[32] = "keyring.pub";
char SECRET_KEYRING_FILENAME[32] = "keyring.sec";
char RANDSEED_FILENAME[32] = "randseed.pgp";

boolean	verbose = FALSE;	/* -l option: display maximum information */

/*
**********************************************************************
*/



boolean pkzipSignature( byte *header )
{
	/*
	**	Return TRUE if header begins with the PKzip signature
	**	Useful for MSDOS only.
	*/

	if ((header[0] == 'P')   && (header[1] == 'K')
	&&  (header[2] == '\03') && (header[3] == '\04'))
		return(TRUE);
	return(FALSE);
}	/* pkzipSignature */


/*
**	Convert to or from external byte order.
**	Note that hilo_swap does nothing if this is a LSB-first CPU.
*/

#define convert2(x,lx)	hilo_swap( (byteptr)&(x), (lx) )
#define convert(x)		convert2( (x), sizeof(x) )

word16 fetch_word16(byte *buf)
/*	Fetches a 16-bit word from where byte pointer is pointing.
	buf points to external-format byteorder array, assuming LSB-first.
*/
{	word16 w0,w1;
	w0 = *buf++;
	w1 = *buf++;
	return((w1<<8) + w0);	
}	/* fetch_word16 */


void get_timestamp(byte *timestamp)
/*	Returns timestamp byte array, in internal byteorder */
{	word32 t;
	t = time(0);
	timestamp[0] = t;		/* fill array in external byte order */
	timestamp[1] = t>>8;
	timestamp[2] = t>>16;
	timestamp[3] = t>>24;
	/* Note that hilo_swap does nothing if this is a LSB-first CPU. */
	hilo_swap(timestamp,4);	/* convert to internal byteorder */
}	/* get_timestamp */


void CToPascal(char *s)
{	/* "xyz\0" --> "\3xyz" ... converts C string to Pascal string */
	int i,j;
	j = string_length(s);
	for (i=j; i!=0; i--)
		s[i] = s[i-1];	/* move everything 1 byte to the right */
	s[0] = j;		/* Pascal length byte at beginning */	
}	/* CToPascal */


void PascalToC( char *s )
{	/* "\3xyz" --> "xyz\0" ... converts Pascal string to C string */
	int i,j;
	for (i=0,j=s[0]; i<j; i++)
		s[i] = s[i+1];	/* move everything 1 byte to the left */
	s[i] = '\0';		/* append C string terminator */
}	/* PascalToC */



int date_ymd(word32 *tstamp, int *year, int *month, int *day)
/*	Given timestamp as seconds elapsed since 1970 Jan 1 00:00:00,
	returns year (1970-2106), month (1-12), day (1-31).
	Not valid for dates after 2100 Feb 28 (no leap day that year).
	Also returns day of week (0-6) as functional return.
*/
{	word32 days,y;
	int m,d,i;
	static short mdays[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
	days = (*tstamp)/86400UL;	/* day 0 is 1970/1/1 */
	days -= 730UL;	/* align days relative to 1st leap year, 1972 */
	y = ((days*4UL)/1461UL);	/* 1972 is year 0 */
	/* reduce to days elapsed since 1/1 last leap year: */ 
	d = days - ((y/4UL)*1461UL);
	*year = y+1972;
	for (i=0; i<48; i++)	/* count months 0-47 */
	{	m = i % 12;
		d -= mdays[m] + (i==1);	/* i==1 is the only leap month */
		if (d < 0)
		{	d += mdays[m] + (i==1);
			break;
		}
	}
	*month = m+1;
	*day = d+1;
	i = (days-2UL) % 7UL;	/* compute day of week 0-6 */
	return(i);	/* returns weekday 0-6; 0=Sunday, 6=Saturday */
}	/* date_ymd */



void show_date(word32 *tstamp)
{	int m,d,y;
	static char *month[12] = 
	{"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
	date_ymd(tstamp,&y,&m,&d);
	fprintf(stderr,"%2d-%s-%02d", d, month[m-1], y % 100);
}	/* show_date */



boolean file_exists(char *filename)
/*	Returns TRUE iff file is can be opened for reading. */
{	FILE *f;
	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(filename,"rb")) == NULL)
		return(FALSE);
	fclose(f);
	return(TRUE);
}	/* file_exists */



#define diskbufsize 1024

int wipeout(FILE *f)
{	/*	Completely overwrite and erase file, so that no sensitive 
		information is left on the disk.  
		NOTE:  File MUST be open for read/write.
	*/

	long flength;
	int count;
	byte textbuf[diskbufsize];

    fseek(f, 0L, SEEK_END);
    flength = ftell(f);
	rewind(f);

	fill0(textbuf,diskbufsize);
	while (flength > 0L)
	{	/* write zeros to the whole file... */
		if (flength < (word32) diskbufsize)
			count = flength;
		else
			count = diskbufsize;
		fwrite(textbuf,1,count,f);
		flength -= count;
	}
	rewind(f);	/* maybe this isn't necessary */
	return(0);	/* normal return */
}	/* wipeout */


int wipefile(char *filename)
{	/*	Completely overwrite and erase file, so that no sensitive 
		information is left on the disk.
	*/
	FILE *f;
	/* open file f for read/write, in binary (not text) mode...*/
	if ((f = fopen(filename,"rb+")) == NULL)
		return(-1);	/* error - file can't be opened */
	wipeout(f);
	fclose(f);
	return(0);	/* normal return */
}	/* wipefile */



#define strhas(s,c) (strchr((s),(c)) != NULL)

boolean strhasany( char *s1, char *s2 )
{	/*	Searches s1 for any of the characters in s2.  
		Returns TRUE if found.
	*/
	while (*s2)
	{	if (strhas(s1,*s2))
			return(TRUE);
		s2++;
	}
	return(FALSE);
}	/* strhasany */


boolean strcontains( char *s1, char *s2 )
{	/*
	**	Searches s1 for s2, without case sensitivity.
	**	Return TRUE if found.
	**
	**	If s2 is an empty string then return TRUE.  This is because,
	**	at least in the world of mathematics, the empty set is contained
	**	in all other sets.  The Microsoft C version 6.0 strstr function
	**	behaves this way but version 5.1 does not, so we need to
	**	explicitly test for the situation. -- ALH 91/2/17
	*/

	if (s2[0] != '\0')
	{
		char buf1[256], buf2[256];	/* scratch buffers */

		strncpy( buf1, s1, 256 );	strlwr( buf1 );	/* converts to lower case */
		strncpy( buf2, s2, 256 );	strlwr( buf2 );	/* converts to lower case */

		if (strstr( buf1, buf2 ) == NULL) 
			return( FALSE );		/* string not found */
	}
	return(TRUE);
}	/*	strcontains	*/


void translate_spaces(char *s)
/* Changes all the underlines to spaces in a string. */
{	while (strchr(s,'_') != NULL)
		*strchr(s,'_') = ' ';
}


boolean no_extension(char *filename)
/*	Returns TRUE if user left off file extension, allowing default. */
{	if (strrchr(filename,'.')==NULL)
		return(TRUE);
	/* see if the last '.' is followed by a backslash...*/ 
	if (*(strrchr(filename,'.')+1) == '\\')
		return(TRUE);	/* just a "..\filename" construct */
	return(FALSE);	/* user specified extension, even if a blank one */
}	/* no_extension */


void drop_extension(char *filename)
{	/* deletes trailing ".xxx" file extension after the period. */
	if (!no_extension(filename))
		*strrchr(filename,'.') = '\0';
}	/* drop_extension */


void default_extension(char *filename, char *extension)
{	/* append filename extension if there isn't one already. */
	if (no_extension(filename))
		strcat(filename,extension);
}	/* default_extension */


void force_extension(char *filename, char *extension)
{	/* change the filename extension. */
	drop_extension(filename);	/* out with the old */
	strcat(filename,extension);	/* in with the new */
}	/* force_extension */


boolean getyesno(char default_answer)
{	/* Get yes/no answer from user, returns TRUE for yes, FALSE for no. */
	char buf[8];
	while (keypress())	/* flush typahead buffer */
		getkey();
	getstring(buf,6,TRUE);	/* echo keyboard input */
	if (strlen(buf)==0)		/* if user didn't give an answer... */
		buf[0] = default_answer;	/* assume default answer */
	buf[0] = tolower(buf[0]);
	return(buf[0]=='y');
}	/* getyesno */


void maybe_force_extension(char *filename, char *extension)
{	/* if user consents to it, change the filename extension. */
	char newname[64];
	if (!strcontains(filename,extension))
	{	strcpy(newname,filename);
		force_extension(newname,extension);
		if (!file_exists(newname))
		{	fprintf(stderr,"\nShould '%s' be renamed to '%s' [Y/n]? ",
				filename,newname);
			if (getyesno('y'))
				rename(filename,newname);
		}
	}
}	/* maybe_force_extension */


/*---------------------------------------------------------------------*/
/* 	Begin uuencode routines.
	This converts a binary file into printable ASCII characters, in a 
	form compatible with the Unix uuencode utility.
	This makes it easier to send encrypted files over a 7-bit channel.
*/

/* ENC is the basic 1 character encoding function to make a char printing */
#define ENC(c) (((c) & 077) + ' ')

/*
 * output one group of 3 bytes, pointed at by p, on file f.
 */
void outdec(char *p, FILE *f)
{
	int c1, c2, c3, c4;

	c1 = *p >> 2;
	c2 = (*p << 4) & 060 | (p[1] >> 4) & 017;
	c3 = (p[1] << 2) & 074 | (p[2] >> 6) & 03;
	c4 = p[2] & 077;
	putc(ENC(c1), f);
	putc(ENC(c2), f);
	putc(ENC(c3), f);
	putc(ENC(c4), f);
}	/* outdec */


/* fr: like read but stdio */
int fr(FILE *fd, char *buf, int cnt)
{
	int c, i;

	for (i=0; i<cnt; i++)
	{
		c = getc(fd);
		if (c == EOF)
			return(i);
		buf[i] = c;
	}
	return (cnt);
}	/* fr */


/*
 * copy from in to out, uuencoding as you go along.
 */
void uuencode(FILE *in, FILE *out)
{
	char buf[80];
	int i, n;

	for (;;)
	{	/* 1 (up to) 45 character line */
		n = fr(in, buf, 45);
		putc(ENC(n), out);

		for (i=0; i<n; i += 3)
			outdec(&buf[i], out);

		putc('\n', out);
		if (n <= 0)
			break;
	}
}	/* uuencode */


int uue_file(char *infile, char *outfile)
{	/* translates infile to uuencode format, writing to outfile */
	FILE *in,*out;
	int mode;

	if (verbose)
		fprintf(stderr,"Converting output to uuecode format.\n");

	/* open input file as binary */
	if ((in = fopen(infile,"rb")) == NULL)
	{   
	    return(1);
	}

	/* open output file as text */
	if ((out = fopen(outfile,"w")) == NULL)
	{	fclose(in);
	    return(1);
	}

	mode = 0666;	/* Assume a reasonable dummy default for file mode */

	fprintf(out,"begin %o %s\n", mode, infile);

	uuencode(in, out);

	fprintf(out,"end\n");
	fclose(out);
	fclose(in);

	return(0);
}	/* uue_file */


/* 	End uuencode routines. */

/*	uudecode routines.  
	Portions derived from unix uudecode utility by Mark Horton.
*/

#define SUMSIZE 64
#define DEC(c)	(((c) - ' ') & 077)    /* single character decode */


int uud_buffer(char *inbuf, char *outbuf, int *outlength)
{
	char *bp;
	boolean has_checksum=FALSE;

	register int j;
	register int n;
	int checksum;
	int status;


		status = 0;
		*outlength = 0;

		/* Pad end of lines in case some editor truncated trailing
		   spaces */

		for (n=0; n<79; n++)  /* search for first \r, \n or \000 */
	    {
		    if (inbuf[n]=='\176')     /* If BITNET made a twiddle, */
				inbuf[n]='\136';     /* we make a caret           */
	    	if (inbuf[n]=='\r' || inbuf[n]=='\n' || inbuf[n]=='\000')
				break;
			if ((inbuf[n] < '\040') || (inbuf[n] > '\137'))
				status = -1;	/* illegal uudecode character */
	    }
		for (; n<79; n++)	/* when found, fill rest of line with space */
		    inbuf[n]=' ';

		inbuf[79]=0;	    /* terminate new string */

		checksum = 0;
		n = DEC(inbuf[0]);
		if (n == 0)
		    return(0);	/* 0 bytes on a line??	Must be the last line */

		if (status) 
			return(status);	/* bad character, out of range */

		bp = &inbuf[1];

		/* FOUR input characters go into each THREE output charcters */

		while (n >= 4)
	    {
		    j = DEC(bp[0]) << 2 | DEC(bp[1]) >> 4; 
			checksum += j;
			outbuf[(*outlength)++]=j; 
	    	j = DEC(bp[1]) << 4 | DEC(bp[2]) >> 2; 
			checksum += j;
			outbuf[(*outlength)++]=j; 
		    j = DEC(bp[2]) << 6 | DEC(bp[3]);
			checksum += j;
			outbuf[(*outlength)++]=j; 
		    checksum = checksum % SUMSIZE;
	    	bp += 4;
		    n -= 3;
	    }

	    j = DEC(bp[0]) << 2 | DEC(bp[1]) >> 4;
		checksum += j;
		if (n >= 1)
			outbuf[(*outlength)++]=j; 
	    j = DEC(bp[1]) << 4 | DEC(bp[2]) >> 2;
		checksum += j;
		if (n >= 2)
			outbuf[(*outlength)++]=j; 
	    j = DEC(bp[2]) << 6 | DEC(bp[3]);
		checksum += j;
		if (n >= 3)
			outbuf[(*outlength)++]=j; 
	    checksum = checksum % SUMSIZE;
	    bp += 4;
	    n -= 3;

		/* The line has been decoded; now check that sum */

		has_checksum |= !isspace(*bp);
		if (has_checksum)			/* Is there a checksum at all?? */
	    	if (checksum != DEC(*bp))	/* Does that checksum match? */
				return(-2);	/* checksum error */

	return(status);	/* normal return */

}	/* uud_buffer */

/*
 * Copy from in to out, decoding as you go.
 * If a return or newline is encountered too early in a line, it is
 * assumed that means that some editor has truncated trailing spaces.
 */
int uudecode(FILE *in, FILE *out)
{
char inbuf[81];
char outbuf[81];
char *bp;
boolean has_checksum=FALSE;

register int j;
int n, status;
int checksum, line;

    for (line = 1; ; line++)	/* for each input line */
	{
		if (fgets(inbuf, sizeof inbuf, in) == NULL)
	    {
		    fprintf(stderr,"ERROR: uudecode input ended unexpectedly!\n");
	    	return(18);
	    }

		status = uud_buffer(inbuf,outbuf,&n);

		if (status == -1)
			fprintf(stderr,"ERROR: bad uudecode character decoding line %d.\n", line);
		if (status == -2)
			fprintf(stderr,"ERROR: checksum mismatch decoding line %d.\n", line);
		if (n==0)	/* zero-length line is the end. */
			break;

		fwrite(outbuf,1,n,out);

    }	/* line */

	return(0);	/* normal return */
}   /* uudecode */


boolean is_uufile(char *infile)
{
	FILE	*in;
	char	inbuf[80];
	char	outbuf[80];
	int i, n, status;

	if ((in = fopen(infile, "r")) == NULL)
    {	/* can't open file */
	    return(FALSE);
    }

    /* search file for header line */
    for (i=0; i<50; i++)	/* give up after 50 lines of garbage */
	{
		if (fgets(inbuf, sizeof inbuf, in) == NULL)
			break;
		else
		{
			if (strncmp(inbuf, "begin ", 6) == 0)
			{
				if (fgets(inbuf, sizeof inbuf, in) == NULL)
					break;
				status = uud_buffer(inbuf,outbuf,&n);
				if (status < 0)
					break;
				fclose(in);
		   		return(TRUE);
			}
		}
	}

	fclose(in);
	return(FALSE);

}	/* is_uufile */


int uud_file(char *infile, char *outfile)
{
FILE	*in, *out;
int	mode;		/* file's mode (from header) */
long	filesize;	/* theoretical file size (from header) */
char	buf[80];
int status;

	if ((in = fopen(infile, "r")) == NULL)
    {
	    fprintf(stderr,"ERROR: can't find %s\n", infile);
	    return(10);
    }

    /* Loop through file, searching for header.  Decode anything with a
       header, complain if there where no headers. */

    /* search file for header line */
    for (;;)
	{
		if (fgets(buf, sizeof buf, in) == NULL)
		{
			fprintf(stderr,"ERROR: no `begin' line!\n");
			fclose(in);
			return(12);
		}
		if (strncmp(buf, "begin ", 6) == 0)
	    	break;
	}

	/* Ignore filename and mode.  Use outfile instead of dest. */
    /* sscanf(buf, "begin %o %s", &mode, dest); */

    /* create output file */
    if ((out = fopen(outfile, "wb")) == NULL)
	{
		fprintf(stderr,"ERROR: can't open output file %s\n", outfile);
		fclose(in);
		return(15);
	}

    status = uudecode(in, out);
	if (status != 0)
	{	fclose(in);
		fclose(out);
		return(status);
	}

    if (fgets(buf, sizeof buf, in) == NULL || strncmp(buf,"end",3))
	{	       /* don't be overly picky about newline ^ */
		fprintf(stderr,"ERROR: no `end' line\n");
		fclose(in);
		fclose(out);
		return(16);
	}

    if (!(fgets(buf,sizeof buf,in) == NULL || strncmp(buf,"size ",3)))
	{
		sscanf(buf, "size %ld", &filesize);
		if (ftell(out) != filesize)
    	{
	    	fprintf(stderr,"ERROR: file should have been %ld bytes long but was %ld.\n", filesize, ftell(out));
	    	return(17);
	    }
	}
	fclose(out);
	fclose(in);
	return(0);	/* normal return */
}   /* uud_file */


/* 	End uudecode routines. */
/*---------------------------------------------------------------------*/



boolean legal_ctb(byte ctb)
{	/* Used to determine if nesting should be allowed. */
	boolean legal;
	byte ctbtype;
	if (!is_ctb(ctb))		/* not even a bonafide CTB */ 
		return(FALSE);
	/* Sure hope CTB internal bit definitions don't change... */
	ctbtype = (ctb & CTB_TYPE_MASK) >> 2;
	/* Only allow these CTB types to be nested... */
	legal = (
			(ctbtype==CTB_PKE_TYPE)
		||	(ctbtype==CTB_SKE_TYPE)
		||	(ctbtype==CTB_CERT_SECKEY_TYPE)
		||	(ctbtype==CTB_CERT_PUBKEY_TYPE)
		||	(ctbtype==CTB_LITERAL_TYPE)
		||	(ctbtype==CTB_COMPRESSED_TYPE)
		||  (ctbtype==CTB_CKE_TYPE)
		/* || (ctbtype==CTB_CONKEY_TYPE) */
		/* || (ctbtype==CTB_MD_TYPE) */
		 );
	return(legal);
}	/* legal_ctb */


/*======================================================================*/

/* MDfile0(MD, f)
** Computes and returns the message digest from a file position to eof.
** Uses RSA Data Security, Inc. MD4 Message Digest Algorithm.
*/
int MDfile0(MDstruct *MD, FILE *f)
{	byte X[64];
	int bytecount;

	MDbegin(MD);
	/* Process 512 bits, or 64 bytes, at a time... */
	while ((bytecount = fread(X, 1, 64, f)) != 0)
		MDupdate(MD, X, bytecount<<3);	/* pass bitcount */
	MDupdate(MD, X, 0);	/* finish with a bitcount of 0 */
	/* MDprint(MD); */

	return(0);	/* normal return */
}	/* MDfile0 */


/* MDfile(MD, filename)
** Computes and returns the message digest for a specified file.
*/
int MDfile(MDstruct *MD, char *filename)
{	FILE *f;
	f = fopen(filename,"rb");
	if (f == NULL) 
	{	fprintf(stderr,"Can't open file '%s'\n",filename);
		return(-1);	/* error return */
	}
	MDfile0(MD, f);
	fclose(f);
	return(0);	/* normal return */
}	/* MDfile */


/* MD_of_buffer(MD, s, len)
** Computes and returns the message digest for buffer s.
** len is the length in bytes of buffer s.
** Uses RSA Data Security, Inc. MD4 Message Digest Algorithm.
*/
void MD_of_buffer(MDstruct *MD, byte *s, int len)
{	int i;

	MDbegin(MD);
	/* Process 512 bits, or 64 bytes, at a time... */
	for (i=0; i+64<=len; i+=64) 
		MDupdate(MD, s+i, 512);
	MDupdate(MD, s+i, (len-i)<<3);	/* finish with short block */
	/* MDprint(MD); */

}	/* MD_of_buffer */


boolean equal_buffers(byte *buf1, byte *buf2, word16 count)
/*	Compares two byte buffers. */
{	while (count--)
		if (*buf1++ != *buf2++)
			return(FALSE);	/* mismatch. */
	return(TRUE);	/* compares OK */
}	/* equal_buffers */


char *buildfilename(char *result, char *fname)
/*	Builds a filename with a complete path specifier from the environmental
	variable PGPPATH.  Assumes MSDOS pathname conventions.
*/
{	char *s = getenv(PGPPATH);
	if (strlen(s) > 50)	/* too long to use */
		s = "";
	strcpy(result,s);
	if (strlen(result) != 0)
		if (result[strlen(result)-1] != '\\')
			strcat(result,"\\");
	strcat(result,fname);
	return(result);
}	/* buildfilename */


int strong_pseudorandom(byte *buf, int bufsize)
/*	Reads BassOmatic random key and random number seed from file, 
	cranks the the seed through the bassrand strong pseudorandom 
	number generator, and writes them back out.  This is used for
	generation of cryptographically strong pseudorandom numbers.
	This is mainly to save the user the trouble of having to 
	type in lengthy keyboard sequences for generation of truly
	random numbers every time we want to make a random BassOmatic
	session key.  This pseudorandom generator will only work if
	the file containing the random seed exists and is not empty.
	If it doesn't exist, it will be automatically created.
	If it exists and is empty or nearly empty, it will not be used.
*/
{	char seedfile[64];	/* Random seed filename */
	FILE *f;
	byte key[64];	/* not to exceed 256 byes in length */
	byte seed[256];	/* not to exceed 256 byes in length */
	int i;
	word32 tstamp; byte *timestamp = (byte *) &tstamp;

	buildfilename(seedfile,RANDSEED_FILENAME);

	if (!file_exists(seedfile))	/* No seed file. Start one... */
	{	f = fopen(seedfile,"wb");	/* open for writing binary */
		if (f==NULL)	/* failed to create seedfile */
			return(-1);	/* error: no random number seed file available */
		fclose(f);	/* close new empty seed file */
		/* kickstart the generator with true random numbers */ 
		fprintf(stderr,"Initializing random seed file...");
		randaccum(8*(sizeof(key)+32)); 
		for (i=1; i<sizeof(key); i++)
			key[i] ^= randombyte();
		for (i=0; i<sizeof(seed); i++)
			seed[i] ^= randombyte();
	}	/* seedfile does not exist */

	else	/* seedfile DOES exist.  Open it and read it. */
	{	f = fopen(seedfile,"rb");	/* open for reading binary */
		if (f==NULL)	/* did open fail? */
			return(-1);	/* error: no random number seed file available */
		/* read BassOmatic random generator key */
		if (fread(key,1,sizeof(key),f) < sizeof(key))	/* empty file? */
		{	/* Empty or nearly empty file means don't use it. */
			fclose(f);
			return(-1);	/* error: no random number seed file available */
		}
		else
			fread(seed,1,sizeof(seed),f); /* read pseudorandom seed */
		fclose(f);
	}	/* seedfile exists */


	get_timestamp(timestamp);
	for (i=0; i<4; i++)
		key[i+1] ^= timestamp[i];

	key[0] = 0x0f;	/* BassOmatic key control byte */

	/* Initialize, key, and seed the BassOmatic pseudorandom generator: */
	initbassrand(key, sizeof(key), seed, sizeof(seed));

	/* Note that the seed will be cycled thru BassOmatic once before use */

	/* Now fill the user's buffer with gobbledygook... */
	while (bufsize--)
		*buf++ = bassrand() ^ randombyte();

	/* now cover up evidence of what user got */
	for (i=1; i<sizeof(key); i++)
		key[i] ^= bassrand() ^ randombyte();
	for (i=0; i<sizeof(seed); i++)
		seed[i] = bassrand() ^ randombyte();

	closebass();	/* close BassOmatic random number generator */

	f = fopen(seedfile,"wb");	/* open for writing binary */
	if (f==NULL)	/* did open fail? */
		return(-1);	/* error: no random number seed file available */
	/* Now at start of file again */
	fwrite(key,1,sizeof(key),f);
	fwrite(seed,1,sizeof(seed),f);
	fclose(f);
	burn(key);		/* burn sensitive data on stack */
	burn(seed);		/* burn sensitive data on stack */
	return(0);	/* normal return */
}	/* strong_pseudorandom */



int make_random_basskey(byte *key, int keybytes)
/*	Make a keybytes-byte random BassOmatic key, plus 1 key control byte.
	The byte count returned includes key control byte.
*/
{	int count;

	key[0] = 0x1f;	/* Default is Military grade BassOmatic key control byte */
	if (keybytes <= 24)
		key[0] = 0x12;	/* Commercial grade BassOmatic key control byte */
	if (keybytes <= 16)
		key[0] = 0x00;	/* Casual grade BassOmatic key control byte */

	if (strong_pseudorandom(key+1, keybytes) == 0)
		return(keybytes+1); /* return length of key, including control byte */

	fprintf(stderr,"Preparing random conventional crypto session key...");

	randaccum(keybytes*8); /* get some random key bits */

	count=0;
	while (++count <= keybytes)
		key[count] = randombyte();

	return(count+1);	/* return length of key, including control byte */

}	/* make_random_basskey */



void copyfile(FILE *f, FILE *g, word32 longcount)
{	/* copy file f to file g, for longcount bytes */
	int count;
	byte textbuf[diskbufsize];
	do	/* read and write the whole file... */
	{
		if (longcount < (word32) diskbufsize)
			count = longcount;
		else
			count = diskbufsize;
		count = fread(textbuf,1,count,f);
		if (count>0)
		{	fwrite(textbuf,1,count,g);
			longcount -= count;
		}
		/* if text block was short, exit loop */
	} while (count==diskbufsize);
	burn(textbuf);	/* burn sensitive data on stack */
}	/* copyfile */


word32 getpastlength(byte ctb, FILE *f)
/*	Returns the length of a packet according to the CTB and 
	the length field. */
{	word32 length;
	int llength;	/* length of length */
	byte buf[8];

	fill0(buf,sizeof(buf));
	length = 0L;
	/* Use ctb length-of-length field... */
	llength = ctb_llength(ctb);	/* either 1, 2, 4, or 8 */
	if (llength==8)		/* 8 means no length field, assume huge length */ 
		return(-1L);	/* return huge length */

	/* now read in the actual length field... */
	if (fread((byteptr) buf,1,llength,f) < llength)
		return (-2L); /* error -- read failure or premature eof */
	/* convert length from external LSB-first format... */
	while (llength--)
	{	length <<= 8;
		length += buf[llength];
	}
	return(length);
}	/* getpastlength */



int bass_file(byte *basskey, int lenbasskey, boolean decryp, 
		FILE *f, FILE *g)
/*	Use BassOmatic in cipher feedback (CFB) mode to encrypt 
	or decrypt a file.  Encrypted key check bytes determine
	if correct BassOmatic key was used to decrypt ciphertext.
*/
{	int count;
	byte textbuf[diskbufsize], iv[256];
#define KEYCHECKLENGTH 4

	/* init CFB BassOmatic key */
	fill0(iv,256);	/* define initialization vector IV as 0 */
	if ( initcfb(iv,basskey,lenbasskey,decryp) < 0 )
		return(-1);	/* Error return should be impossible. */

	if (!decryp)	/* encrypt-- insert key check bytes */
	{	/* key check bytes are 2 copies of 16 random bits */
		textbuf[0] = randombyte();
		textbuf[1] = randombyte();
		textbuf[2] = textbuf[0];
		textbuf[3] = textbuf[1];
		basscfb(textbuf,KEYCHECKLENGTH);
		fwrite(textbuf,1,KEYCHECKLENGTH,g);
	}
	else	/* decrypt-- check for key check bytes */
	{	/* See if there are 2 copies of 16 random bits */
		count = fread(textbuf,1,KEYCHECKLENGTH,f);
		if (count==KEYCHECKLENGTH)
		{	basscfb(textbuf,KEYCHECKLENGTH);
			if ((textbuf[0] != textbuf[2])
				|| (textbuf[1] != textbuf[3]))
			{	return(-2);		/* bad key error */
			}
		}
		else	/* file too short for key check bytes */
			return(-3);		/* error of the weird kind */
	}


	do	/* read and write the whole file in CFB mode... */
	{	count = fread(textbuf,1,diskbufsize,f);
		if (count>0)
		{	basscfb(textbuf,count);
			fwrite(textbuf,1,count,g);
		}
		/* if text block was short, exit loop */
	} while (count==diskbufsize);

	closebass();	/* release BassOmatic resources */
	burn(textbuf);	/* burn sensitive data on stack */
	return(0);	/* should always take normal return */
}	/* bass_file */



int read_mpi(unitptr r, FILE *f, boolean adjust_precision, boolean scrambled)
/*	Read a mutiprecision integer from a file.
	adjust_precision is TRUE iff we should call set_precision to the 
	size of the number read in.
	scrambled is TRUE iff field is encrypted (protects secret key fields).
	Returns the bitcount of the number read in, or returns a negative 
	number if an error is detected.
*/
{	byte buf[MAX_BYTE_PRECISION+2];
	int count;
	word16 bytecount,bitcount,lowcount,highcount;

	mp_init(r,0);

	if ((count = fread(buf,1,2,f)) < 2)
		return (-1); /* error -- read failure or premature eof */

	/* Assumes external format is LSB-first */
	bitcount = (((word16) buf[1]) << 8) + (word16) buf[0];
	if (bits2units(bitcount) > global_precision)
		return(-1);	/* error -- possible corrupted bitcount */

	bytecount = bits2bytes(bitcount);

	count = fread(buf+2,1,bytecount,f);
	if (count < bytecount)
		return(-1);	/* error -- premature eof */

	if (scrambled)	/* decrypt the field */
		basscfb(buf+2,bytecount);

	/*	We assume that the bitcount prefix we read is an exact
		bitcount, not rounded up to the next byte boundary.
		Otherwise we would have to call mpi2reg, then call
		countbits, then call set_precision, then recall mpi2reg
		again.
	*/
	if (adjust_precision && bytecount)
	{	/* set the precision to that specified by the number read. */
		set_precision(bits2units(bitcount+SLOP_BITS));
		/* Now that precision is optimally set, call mpi2reg */
	}

	mpi2reg(r,buf);	/* convert to internal format */
	burn(buf);	/* burn sensitive data on stack */
	return (bitcount);
}	/* read_mpi */



void write_mpi(unitptr n, FILE *f, boolean scrambled)
/*	Write a multiprecision integer to a file.
	scrambled is TRUE iff we should scramble field on the way out,
	which is used to protect secret key fields.
*/
{	byte buf[MAX_BYTE_PRECISION+2];
	short bytecount;
	bytecount = reg2mpi(buf,n);
	if (scrambled)  /* encrypt the field, skipping over the bitcount */
		basscfb(buf+2,bytecount);
	fwrite(buf,1,bytecount+2,f); 
	burn(buf);	/* burn sensitive data on stack */
}	/* write_mpi */



void showkeyID(byte *buf)
/*	Print key fragment, which is an abbreviation or "fingerprint" 
	of the key.
	Show LEAST significant 64 bits (KEYFRAGSIZE bytes) of modulus,
	LSB last.  Yes, that's LSB LAST.
*/
{	short i,j;
	/* fputc('[',stderr); */
	j = KEYFRAGSIZE;
	for (i=KEYFRAGSIZE-1; i>=0; i--)	/* print LSB last */
	{	if (--j < 3)	/* only show bottom 3 bytes of keyID */
			fprintf(stderr,"%02X",buf[i]);
	}
	/* fputc(']',stderr); */
}	/* showkeyID */



void extract_keyID(byteptr keyID, unitptr n)
/*	Extract key fragment from modulus n.  keyID byte array must be
	at least KEYFRAGSIZE bytes long.
*/
{	byte buf[MAX_BYTE_PRECISION+2];
	short i, j;

	fill0(buf,KEYFRAGSIZE+2); /* in case n is too short */
	reg2mpi(buf,n);	/* MUST be at least KEYFRAGSIZE long */
	/* For low-byte-first keyID format, start of keyID is: */
	i = 2;	/* skip over the 2 bytes of bitcount */
	for (j=0; j<KEYFRAGSIZE; )
		keyID[j++] = buf[i++];

}	/* extract_keyID */



void writekeyID(unitptr n, FILE *f)
/*	Write message prefix keyID to a file.
	n is key modulus from which to extract keyID.
*/
{	byte keyID[KEYFRAGSIZE];
	extract_keyID(keyID, n);
	fwrite(keyID,1,KEYFRAGSIZE,f);
}	/* writekeyID */



void showkeyID2(unitptr n)
/*	Derive the key abbreviation fragment from the modulus n, and print it.
	n is key modulus from which to extract keyID.
*/
{	byte keyID[KEYFRAGSIZE];
	extract_keyID(keyID, n);
	showkeyID(keyID);
}	/* showkeyID2 */



boolean checkkeyID(byte *keyID, unitptr n)
/*	Compare specified keyID with one derived from actual key modulus n. */
{
	byte keyID0[KEYFRAGSIZE];
	if (keyID==NULL) /* no key ID -- assume a good match */
		return (TRUE);
	extract_keyID(keyID0, n);
	return(equal_buffers(keyID,keyID0,KEYFRAGSIZE));
}	/* checkkeyID */



/* external function prototype, from rsaio.c */
void dump_unit_array(string s, unitptr r);


short writekeyfile(char *fname, boolean hidekey, byte *timestamp, byte *userid, 
	unitptr n, unitptr e, unitptr d, unitptr p, unitptr q, unitptr u)
/*	Write key components p, q, n, e, d, and u to specified file.
	hidekey is TRUE iff key should be encrypted.
	userid is a length-prefixed Pascal-type character string. 
*/
{	FILE *f;
	byte ctb,c;
	word16 cert_length;
	/* open file f for write, in binary (not text) mode...*/
	if ((f = fopen(fname,"wb")) == NULL)
	{	fprintf(stderr,"\n\aCan't create key file '%s'\n",fname);
		return(-1);
	}
	else
	{
		/*** Begin key certificate header fields ***/
		if (d==NULL)
		{	/* public key certificate */
			ctb = CTB_CERT_PUBKEY;
			cert_length = SIZEOF_TIMESTAMP + userid[0]+1 + (countbytes(n)+2) 
				+ (countbytes(e)+2); /* no crc16 */
		}	/* public key certificate */
		else
		{	/* secret key certificate */
			ctb = CTB_CERT_SECKEY;
				cert_length = SIZEOF_TIMESTAMP + userid[0]+1	
				+ (countbytes(n)+2)
				+ (countbytes(e)+2)	+ (countbytes(d)+2) 
				+ (countbytes(p)+2)	+ (countbytes(q)+2) 
				+ (countbytes(u)+2); /* no crc16 */

		}	/* secret key certificate */

		fwrite(&ctb,1,1,f);		/* write key certificate header byte */
		convert(cert_length);	/* convert to external byteorder */
		fwrite(&cert_length,1,sizeof(cert_length),f);
		hilo_swap(timestamp,4);	/* convert to external LSB-first form */
		fwrite(timestamp,1,4,f); /* write certificate timestamp */
		hilo_swap(timestamp,4);	/* convert back to internal form */
		fwrite(userid,1,userid[0]+1,f);	/* write user ID */
		write_mpi(n,f,FALSE);
		write_mpi(e,f,FALSE);

		if (is_secret_key(ctb))	/* secret key */
		{	
			write_mpi(d,f,hidekey);
			write_mpi(p,f,hidekey);
			write_mpi(q,f,hidekey);
			write_mpi(u,f,hidekey);
		}
		fclose(f);
#ifdef DEBUG
		fprintf(stderr,"\n%d-bit %s key written to file '%s'.\n",
			countbits(n),
			is_secret_key(ctb) ? "secret" : "public" ,
			fname);
#endif
		return(0);
	}
}	/* writekeyfile */


/*======================================================================*/


int get_header_info_from_file(char *infile,  byte *header, int count)
/*	Reads the first count bytes from infile into header. */
{	FILE *f;
	fill0(header,count);
	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(infile,"rb")) == NULL)
		return(-1);
	/* read Cipher Type Byte, and maybe more */
	count = fread(header,1,count,f);
	fclose(f);
    return(count);	/* normal return */
}	/* get_header_info_from_file */



short readkeypacket(FILE *f, boolean hidekey, byte *ctbyte, 
	byte *timestamp, char *userid,
	unitptr n ,unitptr e, unitptr d, unitptr p, unitptr q, unitptr u)
/*	Reads a key certificate from the current file position of file f.
	It will return the ctb, timestamp, userid, public key components 
	n and e, and if the secret key components are present in the 
	certificate and d is not a NULL, it will read and return d, p, q, 
	and u.  The file pointer is left positioned after the certificate.
	hidekey is TRUE iff key is expected to be encrypted.
*/
{
	byte ctb;
	word32 cert_length;
	long file_position;
	int count;

	set_precision(MAX_UNIT_PRECISION);	/* safest opening assumption */

	/*** Begin certificate header fields ***/
	*ctbyte = 0;	/* assume no ctbyte for caller at first */
	count = fread(&ctb,1,1,f);	/* read key certificate CTB byte */
	if (count==0) return(-1);	/* premature eof */
	*ctbyte = ctb;	/* returns type to caller */
	if ((ctb != CTB_CERT_PUBKEY) && (ctb != CTB_CERT_SECKEY))
		return(-2);	/* not a key certificate */

	cert_length = getpastlength(ctb, f); /* read certificate length */

	if (cert_length > MAX_KEYCERT_LENGTH-3)
		return(-3);	/* bad length */

	fread(timestamp,1,4,f);	/* read certificate timestamp */
	/* note that hilo_swap does nothing if this is a LSB-first CPU */
	hilo_swap(timestamp,4); /* convert from external LSB-first form */
	count = fread(userid,1,1,f);	/* read user ID length byte */
	if (count==0) return(-1);	/* premature eof */
	fread(userid+1,1,userid[0],f); /* read rest of user ID */
	/*** End certificate header fields ***/

	/* We're past certificate headers, now look at some key material...*/

	if (read_mpi(n,f,TRUE,FALSE) < 0)
		return(-4);	/* data corrupted, return error */

	/* Note that precision was adjusted for n */

	if (read_mpi(e,f,FALSE,FALSE) < 0)
		return(-4);	/* data corrupted, error return */

	cert_length -= SIZEOF_TIMESTAMP + userid[0]+1 + 
		(countbytes(n)+2) + (countbytes(e)+2);

	if (d==NULL)	/* skip rest of this key certificate */
	{	fseek(f, cert_length, SEEK_CUR);
		cert_length = 0;	/* because we are skipping secret fields */
	}
	else	/* d is not NULL */
	{	if (is_secret_key(ctb))
		{
			if (read_mpi(d,f,FALSE,hidekey) < 0)
				return(-4);	/* data corrupted, error return */
			if (read_mpi(p,f,FALSE,hidekey) < 0)
				return(-4);	/* data corrupted, error return */
			if (read_mpi(q,f,FALSE,hidekey) < 0)
				return(-4);	/* data corrupted, error return */
   	
			/* use register 'u' briefly as scratchpad */
			mp_mult(u,p,q);	/* compare p*q against n */
			if (mp_compare(n,u)!=0)	/* bad pass phrase? */
				return(-5);	/* possible bad pass phrase, error return */
			/* now read in real u */
			if (read_mpi(u,f,FALSE,hidekey) < 0)
				return(-4);	/* data corrupted, error return */

			cert_length -= (countbytes(d)+2) + (countbytes(p)+2) 
				+ (countbytes(q)+2) + (countbytes(u)+2);

		}	/* secret key */
		else /* not a secret key */
		{	mp_init(d,0);
			mp_init(p,0);
			mp_init(q,0);
			mp_init(u,0);
		}
	}	/* d != NULL */

	if (cert_length != 0)
	{	fprintf(stderr,"\n\aCorrupted key.  Bad length, off by %d bytes.\n",
			(signed int) cert_length);
		return(-4);	/* data corrupted, error return */
	}

	return(0);	/* normal return */

}	/* readkeypacket */



int getpublickey(boolean giveup, boolean showkey, char *keyfile, 
	long *file_position, int *pktlen, byte *keyID, byte *timestamp, 
	byte *userid, unitptr n, unitptr e)
/*	keyID contains key fragment we expect to find in keyfile.
	If keyID is NULL, then userid contains a C string search target of
	userid to find in keyfile.
	keyfile is the file to begin search in, and it may be modified
	to indicate true filename of where the key was found.  It can be
	either a public key file or a secret key file.
	file_position is returned as the byte offset within the keyfile 
	that the key was found at.
	giveup is TRUE iff we are just going to do a single file search only.
*/
{
	int keytype;	/* 1 for secret key, 0 for public key */
	byte ctb;	/* returned by readkeypacket */
	FILE *f;
	int status;
	boolean keyfound = FALSE;
	boolean secret;		/* indicates we are called by getsecretkey */
	char userid0[256];	/* C string format */

	userid0[0] = '\0';
	secret = strcontains(keyfile,SEC_EXTENSION);

	if (keyID==NULL)	/* then userid has search target */
		strcpy(userid0,userid);

top:
	if (secret)
		default_extension(keyfile,SEC_EXTENSION);
	else
		default_extension(keyfile,PUB_EXTENSION);

	if (!file_exists(keyfile))
	{	if (giveup)
			return(-1);	/* give up, error return */
		fprintf(stderr,"\nKeyring file '%s' does not exist. ",keyfile);
		goto nogood;
	}
	if (verbose) fprintf(stderr,"\nSearching key ring file '%s'.\n",keyfile);

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(keyfile,"rb")) == NULL)
		return(-1);	/* error return */

	while (TRUE) 
	{
		*file_position = ftell(f);
		status = readkeypacket(f,FALSE,&ctb,timestamp,userid,n,e,
				NULL,NULL,NULL,NULL);
		/* Note that readkeypacket has called set_precision */

		if (status == -1)	/* end of file */
			break;

		if (status < -1)
		{	fprintf(stderr,"\n\aCould not read key from file '%s'.\n",
				keyfile);
			fclose(f);	/* close key file */
			return(-1);
		}

		/* keyID contains key fragment.  Check it against n from keyfile. */
		if (keyID!=NULL)
			keyfound = checkkeyID(keyID,n);
		else
		{	/* userid0 is already a C string */
			PascalToC(userid);	/* for C string functions */
			keyfound = strcontains(userid,userid0); /* any matching subset? */
			/* keyfound = (strcmp(userid,userid0)==0); /* exact match? */
			CToPascal(userid);
		}

		if (keyfound)
		{	*pktlen = (ftell(f) - *file_position);
			if (showkey)
			{	PascalToC(userid);	/* for display */
				fprintf(stderr,"\nKey for user ID: %s\n",userid);
				CToPascal(userid);
				fprintf(stderr,"%d-bit key, Key ID ",countbits(n));
				showkeyID2(n);
				fprintf(stderr,", created %s",ctime((long *)timestamp));
			}
			fclose(f);
			return(0);	/* normal return */
		}
	}	/* while TRUE */

	fclose(f);	/* close key file */

	if (giveup)
		return(-1);	/* give up, error return */

	if (keyID!=NULL)
	{
		fprintf(stderr,"\n\aKey matching expected Key ID ");
		showkeyID(keyID);
		fprintf(stderr," not found in file '%s'.\n",keyfile);
	}
	else
	{	fprintf(stderr,"\n\aKey matching userid '%s' not found in file '%s'.\n",
			userid0,keyfile);
	}

nogood:
	if (giveup)
		return(-1);	/* give up, error return */

	if (secret)
		fprintf(stderr,"Enter secret key filename: ");
	else
		fprintf(stderr,"Enter public key filename: ");

	getstring(keyfile,59,TRUE);	/* echo keyboard input */
	if (strlen(keyfile) > 0)
		goto top;

	return(-1);	/* give up, error return */

}	/* getpublickey */



int getsecretkey(byte *keyID, byte *timestamp, byte *userid, 
	unitptr n, unitptr e, unitptr d, unitptr p, unitptr q, unitptr u)
/*	keyID contains key fragment we expect to find in keyfile.
	If keyID is NULL, then userid contains search target of
	userid to find in keyfile.
*/
{
	byte ctb;	/* returned by readkeypacket */
	FILE *f;
	char keyfile[64];	/* for getpublickey */
	long file_position;
	int pktlen;	/* unused, just to satisfy getpublickey */
	int status;
	boolean hidekey = FALSE;	/* TRUE iff secret key is encrypted */
	char passphrase[256];
	byte iv[256];	/* for BassOmatic CFB mode */
	int guesses = 3;

	buildfilename(keyfile,SECRET_KEYRING_FILENAME); /* use default pathname */

	status = getpublickey(FALSE, TRUE, keyfile, &file_position, &pktlen,
			keyID, timestamp, userid, n, e);
	if (status < 0)
		return(status);	/* error return */

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(keyfile,"rb")) == NULL)
		return(-1);	/* error return */

	/* First guess is null password, so hidekey is FALSE */

	do	/* until good password */
	{	/* init CFB BassOmatic key */
		if (hidekey)
		{	fill0(iv,256);	/* define initialization vector IV as 0 */
			if ( initcfb(iv,passphrase,string_length(passphrase),TRUE) < 0 )
			{	fclose(f);	/* close key file */
				return(-1);
			}
		}
		burn(passphrase);	/* burn sensitive data on stack */
		fseek(f,file_position,SEEK_SET); /* reposition file to key */
		status = readkeypacket(f,hidekey,&ctb,timestamp,userid,n,e,d,p,q,u);
		if (hidekey) 
			closebass();	/* release BassOmatic resources */

		if (status == -5)	/* bad pass phrase status */
		{	if (guesses!=3)	/* not first guess of null password? */
				fprintf(stderr,"\n\aUnreadable secret key.  Possible bad pass phrase.\n");
			if (--guesses)	/* not ran out of guesses yet */
			{	fprintf(stderr,"\nYou need a pass phrase to unlock your RSA secret key. ");
				hidekey = (getpassword(passphrase,1,0x0f) > 0);
				continue;	/* take it from the top */
			}	/* more guesses to go */
		}
		if (status < 0)
		{	fprintf(stderr,"\n\aCould not read key from file '%s'.\n",
				keyfile);
			fclose(f);	/* close key file */
			return(-1);
		}
	}	while (status < 0);	/* until key reads OK, with good password */

	fclose(f);	/* close key file */

	if (!hidekey) 
		fprintf(stderr,"\nAdvisory warning: This RSA secret key is not protected by a passphrase.\n");
	else
		fprintf(stderr,"Pass phrase is good.  ");

	/* Note that readkeypacket has called set_precision */

	if (testeq(d,0))	/* didn't get secret key components */
	{	fprintf(stderr,"\n\aKey file '%s' is not a secret key file.\n",keyfile);
		return(-1);
	}

	return(0);	/* normal return */

}	/* getsecretkey */



int make_signature_certificate(byte *certificate, MDstruct *MD, 
	byte *userid, unitptr n, unitptr d, unitptr p, unitptr q, unitptr u)
/*	Constructs a signed message digest in a signature certificate.
	Returns total certificate length in bytes, or returns negative 
	error status.
*/
{	
	byte inbuf[MAX_BYTE_PRECISION], outbuf[MAX_BYTE_PRECISION];
	byte mdpacket[32];
	byte *mdbufptr;
	int i,j,certificate_length,blocksize,bytecount;
	word16 useridlength,certsig_length,mdp_length,ske_length;
	word32 tstamp; byte *timestamp = (byte *) &tstamp;
	byte keyID[KEYFRAGSIZE];

	/*	Note that RSA key must be at least big enough to encipher a 
		complete message digest packet in a single RSA block. */

	blocksize = countbytes(n)-1;	/* size of a plaintext block */
	if (blocksize < 31)
	{	fprintf(stderr,"\n\aError: RSA key length must be at least 256 bits.\n");
		return(-1);
	}

	get_timestamp(timestamp);	/* Timestamp when signature was made */
	hilo_swap(timestamp,4); /* convert to external LSB-first form */

	fill0(mdpacket,sizeof(mdpacket));
	mdpacket[0] = CTB_MD;	/* Message Digest type */
	/* mdp_length includes algorithm byte, MD, and timestamp. */
	mdp_length = 1+16+4; /* message digest packet length */
	/* MD packet length does not include itself or CTB prefix: */
	mdpacket[1] = mdp_length;
	mdpacket[2] = MD4_ALGORITHM_BYTE;	/* select MD4 algorithm */

	mdbufptr = (byte *) (MD->buffer);	/* point at actual message digest */
	for (i=0; i<16; i++)
		mdpacket[i+3] = *mdbufptr++;	/* Assumes LSB-first order */
	/* Stick a timestamp in here, before signing... */
	/* timestamp already in external format */
	for (j=0; j<SIZEOF_TIMESTAMP; j++,i++)
		mdpacket[i+3] = timestamp[j];
	
	/* Pre-block mdpacket, and convert to INTERNAL byte order: */
	preblock((unitptr)inbuf, mdpacket, mdp_length+2, n, TRUE, NULL);

	fprintf(stderr,"Just a moment-- ");	/* RSA will take a while. */

	/* do RSA signature calculation: */
	rsa_decrypt((unitptr)outbuf,(unitptr)inbuf,d,p,q,u);

	bytecount = reg2mpi(outbuf,(unitptr)outbuf); /* convert to external format */
	/*	outbuf now contains a MDSB in external byteorder form.
		Now make a complete signature certificate from this.
	*/

	certificate_length = 0;

	/* SKE is Secret Key Encryption (signed).  Append CTB for signed msg. */
	certificate[certificate_length++] = CTB_SKE;

	ske_length = KEYFRAGSIZE + bytecount+2;
	/* SKE packet length does not include itself or CTB prefix: */
	certificate[certificate_length++] = ske_length & 0xff;
	certificate[certificate_length++] = (ske_length >> 8) & 0xff;

	/* Now append keyID... */
	extract_keyID(keyID, n);	/* gets keyID */
	for (i=0; i<KEYFRAGSIZE; i++)
		certificate[certificate_length++] = keyID[i];

	/* Now append the RSA-signed message digest packet: */
	for (i=0; i<bytecount+2; i++)
		certificate[certificate_length++] = outbuf[i];

	fputc('.',stderr);	/* Signal RSA signature completion. */

	burn(inbuf);	/* burn sensitive data on stack */
	burn(outbuf);	/* burn sensitive data on stack */

	return(certificate_length);	/* return length of certificate in bytes */

}	/* make_signature_certificate */


/*======================================================================*/


int signfile(boolean nested, boolean separate_signature,
		char *mcguffin, char *infile, char *outfile)
/*	Write an RSA-signed message digest of input file to specified 
	output file, and append input file to output file.
	separate_signature is TRUE iff we should not append the 
	plaintext to the output signature certificate.
*/
{	
	FILE *f;
	FILE *g;
	byte ctb;	/* Cipher Type Byte */
	int certificate_length;	/* signature certificate length */
	byte certificate[MAX_SIGCERT_LENGTH];

	{	/* temporary scope for some buffers */
		word32 tstamp; byte *timestamp = (byte *) &tstamp;		/* key certificate timestamp */
		byte userid[256];
		MDstruct MD;
		unit n[MAX_UNIT_PRECISION], e[MAX_UNIT_PRECISION], d[MAX_UNIT_PRECISION];
		unit p[MAX_UNIT_PRECISION], q[MAX_UNIT_PRECISION], u[MAX_UNIT_PRECISION];

		set_precision(MAX_UNIT_PRECISION);	/* safest opening assumption */

		if (verbose)
			fprintf(stderr,"\nPlaintext file: %s, signature file: %s\n",
			infile,outfile);

		if (MDfile(&MD, infile) < 0)
			return(-1);	/* problem with input file.  error return */

		strcpy(userid,mcguffin);	/* Who we are looking for */

		if (getsecretkey(NULL, timestamp, userid, n, e, d, p, q, u) < 0)
			return(-1);	/* problem with secret key file. error return. */

		certificate_length = make_signature_certificate(certificate, &MD, userid, n, d, p, q, u);

	}	/* end of scope for some buffers */

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(infile,"rb")) == NULL)
	{	fprintf(stderr,"\n\aCan't open plaintext file '%s'\n",infile);
		return(-1);
	}

	/* open file g for write, in binary (not text) mode...*/
	if ((g = fopen(outfile,"wb")) == NULL)
	{	fprintf(stderr,"\n\aCan't create signature file '%s'\n",outfile);
		fclose(f);
		return(-1);
	}

	/* write out certificate record to outfile ... */
	fwrite(certificate,1,certificate_length,g);
	
	if (!separate_signature)
	{	
		if (!nested)
		{	ctb = CTB_LITERAL;
			fwrite( &ctb, 1, 1, g );	/*	write LITERAL CTB */
			/* No CTB packet length specified means indefinite length. */
		}
		copyfile(f,g,-1UL);	/* copy rest of file from file f to g */
	}

	fclose(g);
	fclose(f);
	return(0);	/* normal return */

}	/* signfile */


/*======================================================================*/

int check_signaturefile(char *infile, char *outfile)
{
	byte ctb,ctb2;	/* Cipher Type Bytes */
	char keyfile[64];	/* for getpublickey */
	long fp;	/* unused, just to satisfy getpublickey */
	int pktlen;	/* unused, just to satisfy getpublickey */
	FILE *f;
	FILE *g;
	long start_text;	/* marks file position */
	int i,count,blocksize;
	word16 SKElength, cert_length;
	word32 LITlength;
	int certificate_length;	/* signature certificate length */
	byte certbuf[MAX_SIGCERT_LENGTH];
	byteptr certificate; /* for parsing certificate buffer */
	unit n[MAX_UNIT_PRECISION], e[MAX_UNIT_PRECISION];
	byte inbuf[MAX_BYTE_PRECISION];
	byte outbuf[MAX_BYTE_PRECISION];
	byte keyID[KEYFRAGSIZE];
	word32 tstamp;
	byte *timestamp = (byte *) &tstamp;		/* key certificate timestamp */
	byte userid[256];
	MDstruct MD;
	boolean separate_signature;
	
	fill0( keyID, KEYFRAGSIZE );

	set_precision(MAX_UNIT_PRECISION);	/* safest opening assumption */

	buildfilename(keyfile,PUBLIC_KEYRING_FILENAME); /* use default pathname */

	if (verbose)
		fprintf(stderr,"\nSignature file: %s, output file: %s\n",
		infile,outfile);

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(infile,"rb")) == NULL)
	{	fprintf(stderr,"\n\aCan't open ciphertext file '%s'\n",infile);
		return(-1);
	}

	/******************** Read header CTB and length field ******************/

	fread(&ctb,1,1,f);	/* read certificate CTB byte */
	certificate = certbuf;
	*certificate++ = ctb;	/* copy ctb into certificate */

	if (!is_ctb(ctb))
	{	fprintf(stderr,"\n\a'%s' is not a cipher file.\n",infile);
		goto err1;
	}

	cert_length = getpastlength(ctb, f); /* read certificate length */
	certificate += ctb_llength(ctb);	/* either 1, 2, 4, or 8 */
	if (cert_length > MAX_SIGCERT_LENGTH-3)
	{	fprintf(stderr,"\n\aSignature file '%s' has huge packet length field.\n",infile);
		goto err1;
	}

	/* read whole certificate: */
	if (fread((byteptr) certificate, 1, cert_length, f) < cert_length)
	{	fprintf(stderr,"\n\aSignature file '%s' has bad packet length field.\n",infile);
		goto err1;
	}

	if (!is_ctb_type(ctb,CTB_SKE_TYPE))
	{	fprintf(stderr,"\n\a'%s' is not a signature file.\n",infile);
		goto err1;
	}

	for (i=0; i<KEYFRAGSIZE; i++)
		keyID[i] = *certificate++; /* copy rest of key fragment */

	mpi2reg((unitptr)inbuf,certificate);	/* get signed message digest */
	certificate += countbytes((unitptr)inbuf)+2;

	if ((certificate-certbuf) != cert_length+3)
	{	fprintf(stderr,"\n\aBad length in signature certificate.  Off by %d.\n",
			(signed int) ((certificate-certbuf) - (cert_length+3)));
		goto err1;
	}

	start_text = ftell(f);	/* mark position of text for later */

	if (fread(outbuf,1,1,f) < 1)	/* see if any plaintext is there */
	{	/*	Signature certificate has no plaintext following it.
			Must be in another file.  Go look. */
		separate_signature = TRUE;
		fclose(f);
		fprintf(stderr,"\nFile '%s' has signature, but with no text.",infile);
		if (file_exists(outfile))
		{	fprintf(stderr,"\nText is assumed to be in file '%s'.\n",outfile);
		}
		else
		{	fprintf(stderr,"\nPlease enter filename of text that signature applies to: ");
			getstring(outfile,59,TRUE);	/* echo keyboard */
			if (strlen(outfile) == 0)
				return(-1);
		}
		/* open file f for read, in binary (not text) mode...*/
		if ((f = fopen(outfile,"rb")) == NULL)
		{	fprintf(stderr,"\n\aCan't open file '%s'\n",outfile);
			return(-1);
		}
		start_text = ftell(f);	/* mark position of text for later */
	}	/* had to open new input file */
	else
	{	separate_signature = FALSE;
		/*	We just read 1 byte, so outbuf[0] should contain a ctb, 
			maybe a CTB_LITERAL byte. */
		ctb2 = outbuf[0];
		if (is_ctb(ctb2) && is_ctb_type(ctb2,CTB_LITERAL_TYPE))
		{	/* skip over the CTB_LITERAL header to compute signature */
			LITlength = getpastlength(ctb2, f); /* read packet length */
			start_text = ftell(f);	/* mark position of text for later */
			/* Now we are 1 byte past the CTB_LITERAL header. */
		}
	}


	/* Use keyID prefix to look up key... */

	/*	Get and validate public key from a key file: */
	if (getpublickey(FALSE, verbose, keyfile, &fp, &pktlen, 
			keyID, timestamp, userid, n, e) < 0)
	{	/* Can't get public key.  Complain and process file copy anyway. */
		fprintf(stderr,"\n\aWARNING: Can't find the right public key-- can't check signature integrity.\n");
	}	/* Can't find public key */
	else	/* got good public key, now use it to check signature...*/
	{
		if (testeq(e,0))	/* Means secret key has been compromised */
		{	PascalToC(userid);
			fprintf(stderr,"\n\aWarning: Secret key compromised for userid \"%s\".",userid);
			fprintf(stderr,"\nThus this public key cannot be used.\n");
			goto err1;
		}

		/* Recover message digest via public key */
		mp_modexp((unitptr)outbuf,(unitptr)inbuf,e,n);

		/* Unblock message digest, and convert to external byte order: */
		count = postunblock(outbuf, (unitptr)outbuf, n, TRUE, TRUE);
		if (count < 0)
		{	fprintf(stderr,"\n\aBad RSA decrypt: checksum or pad error during unblocking.\n");
			goto err1;
		}

		fputc('.',stderr);	/* Signal RSA completion. */

		/* outbuf should contain message digest packet */
		/*==================================================================*/
		/* Look at nested stuff within RSA block... */

		if (!is_ctb_type(outbuf[0],CTB_MD_TYPE))
		{ 	fprintf(stderr,"\aNested info is not a message digest packet.\n");
			goto err1;
		}

		if (outbuf[2] != MD4_ALGORITHM_BYTE)
		{	fprintf(stderr,"\a\nUnrecognized message digest algorithm.\n");
			goto err1;
		}

		/* Reposition file to where that plaintext begins... */
		fseek(f,start_text,SEEK_SET); /* reposition file from last ftell */

		MDfile0(&MD,f);	/* compute a message digest from rest of file */

		hilo_swap(outbuf+19,4); /* convert timestamp from external LSB-first form */
		PascalToC(userid);	/* for display */

		/* now compare computed MD with claimed MD */
		if (!equal_buffers((byte *)(MD.buffer), outbuf+3, 16))
		{	fprintf(stderr,"\a\nWARNING: Bad signature, doesn't match file contents!\a\n");
			fprintf(stderr,"\nBad signature from user \"%s\".\n",userid);
			fprintf(stderr,"Signature made %s",ctime((long *)(outbuf+19))); /* '\n' */
			goto xnormal;	/* normal exit */
		}

		fprintf(stderr,"\nGood signature from user \"%s\".\n",userid);
		fprintf(stderr,"Signature made %s",ctime((long *)(outbuf+19))); /* '\n' */

	}	/* Found correct public key */

	/* Reposition file to where that plaintext begins... */
	fseek(f,start_text,SEEK_SET); /* reposition file from last ftell */

	if (separate_signature)
		fprintf(stderr,"\nSignature and text are separate.  No output file produced. ");
	else	/* signature precedes plaintext in file... */
	{	/* produce a plaintext output file from signature file */
		if (file_exists(outfile))
		{	fprintf(stderr,"\n\aOutput file '%s' already exists.  Overwrite (y/N)? ",outfile);
			if (!getyesno('n'))	/* user said don't do it. */
				goto err1;	/* abort operation */
		}
		/* open file g for write, in binary (not text) mode...*/
		if ((g = fopen(outfile,"wb")) == NULL)
		{	fprintf(stderr,"\n\aCan't create plaintext file '%s'\n",outfile);
			goto err1;
		}
		copyfile(f,g,-1UL);	/* copy rest of file from file f to g */
		fclose(g);
	}

xnormal:
	burn(inbuf);	/* burn sensitive data on stack */
	burn(outbuf);	/* burn sensitive data on stack */
	fclose(f);
	if (separate_signature)
		return(0);	/* normal return, no nested info */
	if (is_ctb(ctb2) && is_ctb_type(ctb2,CTB_LITERAL_TYPE))
		/* we already stripped away the CTB_LITERAL */
		return(0);	/* normal return, no nested info */
	/* Otherwise, it's best to assume a nested CTB */
	return(1);	/* nested information return */

err1:
	burn(inbuf);	/* burn sensitive data on stack */
	burn(outbuf);	/* burn sensitive data on stack */
	fclose(f);
	return(-1);	/* error return */

}	/* check_signaturefile */



/*======================================================================*/
int squish_and_bass_file(byte *basskey, int lenbasskey, FILE *f, FILE *g)
{
	FILE *t;
	byte header[4];
	byte ctb;

	/*
	**	Create a temporary file 't' and compress our input file 'f' into
	**	't'.  If we get a good compression ratio then use file 't' for
	**	input and write a CTB_COMPRESSED prefix.
	**	But, if the file looks like a PKZIP file then skip our compression.
	*/

	fread( header, 1, 4, f );
	rewind( f );

	if (pkzipSignature( header ))
		t = f;
	else
	if ((t = tmpfile()) != NULL)
	{
		extern int lzhEncode( FILE *, FILE * );

		if (verbose) fprintf(stderr, "Compressing plaintext..." );

		ctb = CTB_COMPRESSED; 		/* use compression prefix CTB */
		fwrite( &ctb, 1, 1, t );	/* write CTB_COMPRESSED */
		/* No CTB packet length specified means indefinite length. */
		ctb = LZH_ALGORITHM_BYTE; 	/* use lzh compression */
		fwrite( &ctb, 1, 1, t );	/* write LZH algorithm byte */

		/* lzhEncode returns the ratio of file size t to size f. */

		if (lzhEncode( f, t) < 9)
		{
			/*	Compression made the input file smaller by at least
				10 per cent, so use the 't' file. */

			if (verbose) fprintf(stderr, "compressed.  " );

			rewind( t );
		}
		else
		{
			/*	Compression made no significant difference in size so
				pass the input file along as it is.  Close and remove
				the temporary file. */

			if (verbose) fprintf(stderr, "incompressible.  " );

			wipeout( t );
			fclose( t );
			rewind( f );
			t = f;
		}
	}
	else
		t = f;

	/*	Now write out file thru BassOmatic ... */

	ctb = CTB_CKE;			/*	CKE is Conventional Key Encryption */
	fwrite( &ctb, 1, 1, g );	/* write CTB_CKE */
	/* No CTB packet length specified means indefinite length. */

	bass_file( basskey, lenbasskey, FALSE, t, g ); /* encrypt file */

	if (t != f)	
	{	wipeout( t );
		fclose( t );  /* close and remove the temporary file */
	}

	return(0);	/* normal return */

}	/* squish_and_bass_file */


#define NOECHO1 1	/* Disable password from being displayed on screen */
#define NOECHO2 2	/* Disable password from being displayed on screen */

int bass_encryptfile(boolean nested, char *infile, char *outfile)
{
	FILE *f;	/* input file */
	FILE *g;	/* output file */
	byte basskey[256];
	int basskeylen;	/* must get no bigger than sizeof(basskey)-2 */

	if (verbose)
		fprintf(stderr,"\nPlaintext file: %s, ciphertext file: %s\n",
		infile,outfile);

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen( infile, "rb" )) == NULL)
	{
		fprintf(stderr,"\n\aCan't open plaintext file '%s'\n", infile );
		return(-1);
	}

	/* open file g for write, in binary (not text) mode...*/
	if ((g = fopen( outfile, "wb" )) == NULL)
	{
		fprintf(stderr,"\n\aCan't create ciphertext file '%s'\n", outfile );
		fclose(f);
		return(-1);
	}

	/* Get BassOmatic password with leading BassOmatic control byte: */
	/* Default is Military grade BassOmatic key control byte */
	if (getpassword(basskey,NOECHO2,0x1f) <= 0)
		return(-1);

	basskeylen = strlen(basskey);

	/* Now compress the plaintext and encrypt it with BassOmatic... */
	squish_and_bass_file( basskey, basskeylen, f, g );

	burn(basskey);	/* burn sensitive data on stack */

	fclose(g);
	fclose(f);

	return(0);

}	/* bass_encryptfile */


/*======================================================================*/


int encryptfile(boolean nested, char *mcguffin, char *infile, char *outfile)
{
	byte ctb;
	byte ctbCKE = CTB_CKE;
	byte randompad[MAX_BYTE_PRECISION];	/* buffer of random pad bytes */
	int i,blocksize,ckp_length,PKElength,bytecount;
	FILE *f;
	FILE *g;
	FILE *t;
	byte header[4];
	unit n[MAX_UNIT_PRECISION], e[MAX_UNIT_PRECISION];
	byte inbuf[MAX_BYTE_PRECISION];
	byte outbuf[MAX_BYTE_PRECISION];
	word32 tstamp; byte *timestamp = (byte *) &tstamp;		/* key certificate timestamp */
	byte userid[256];
	byte basskey[64]; /* must be big enough for make_random_basskey */
	int basskeylen;	/* must get no bigger than sizeof(basskey)-2 */
	char keyfile[64];	/* for getpublickey */
	long fp;	/* unused, just to satisfy getpublickey */
	int pktlen;	/* unused, just to satisfy getpublickey */


	buildfilename(keyfile,PUBLIC_KEYRING_FILENAME); /* use default pathname */

	if (verbose)
		fprintf(stderr,"\nPlaintext file: %s, ciphertext file: %s\n",
		infile,outfile);

	strcpy(userid,mcguffin);	/* Who we are looking for (C string) */

	/*	Get and validate public key from a key file: */
	if (getpublickey(FALSE, TRUE, keyfile, &fp, &pktlen, NULL, timestamp, userid, n, e) < 0)
	{	return(-1);
	}

	if (testeq(e,0))	/* Means secret key has been compromised */
	{	PascalToC(userid);
		fprintf(stderr,"\n\aWarning: Secret key compromised for userid \"%s\".",userid);
		fprintf(stderr,"\nThus this public key cannot be used.\n");
		return(-1);
	}


	/* set_precision has been properly called by getpublickey */

	/*	Note that RSA key must be at least big enough to encipher a 
		complete conventional key packet in a single RSA block.
		The BassOmatic key packet is 28 bytes long, which requires 
		an RSA key 32 bytes (256 bits) long.  
		If we implemented DES, the DES key packet is 37 bytes long 
		(with IV, prewhitener and postwhitener), requiring an RSA 
		key 41 bytes (328 bits) long.
	*/

	blocksize = countbytes(n)-1;	/* size of a plaintext block */
	if (blocksize < 31)
	{	fprintf(stderr,"\n\aError: RSA key length must be at least 256 bits.\n");
		return(-1);
	}

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen( infile, "rb" )) == NULL)
	{
		fprintf(stderr,"\n\aCan't open plaintext file '%s'\n", infile );
		return(-1);
	}

	/* open file g for write, in binary (not text) mode...*/
	if ((g = fopen( outfile, "wb" )) == NULL)
	{
		fprintf(stderr,"\n\aCan't create ciphertext file '%s'\n", outfile );
		fclose(f);
		return(-1);
	}

	/*	Now we have to time some user keystrokes to get some random 
		bytes for generating a random BassOmatic key.
		We would have to solicit fewer keystrokes for random BassOmatic 
		key generation if we had already accumulated some keystrokes 
		incidental to some other purpose, such as asking for a password 
		to decode an RSA secret key so that a signature could be applied 
		to the message before encrypting it.
	*/

	basskeylen = 32;	/* Default is big BassOmatic key */
	if (blocksize < 64)		/* <= 512 bits */ 
		basskeylen = 24;
	if (blocksize < 36) 	/* <= 288 bits */
		basskeylen = 16;
	ckp_length = make_random_basskey(basskey,basskeylen);
	/* Returns a basskeylen+1 byte random BassOmatic key */

	outbuf[0] = CTB_CONKEY;	/* conventional key packet */

	ckp_length += 1; /* add length of algorithm field */
	/* Conventional key packet length does not include itself or CTB prefix: */
	outbuf[1] = ckp_length;

	outbuf[2] = BASS_ALGORITHM_BYTE;	/* select BassOmatic algorithm */

	for (i=0; i<ckp_length-1; i++)
		outbuf[3+i] = basskey[i];

	/*
	**	Messages encrypted with a public key should use random padding, 
	**	while messages "signed" with a secret key should use constant 
	**	padding.
	*/

	for (i = 0; i < (blocksize - (ckp_length + 2)); i++)
		randompad[i] = randombyte();

	/*
	**	Note that RSA key must be at least big enough to encipher a 
	**	complete conventional key packet in a single RSA block.
	*/

	/* ckp_length+2 is conventional key packet length. */

	preblock( (unitptr)inbuf, outbuf, ckp_length+2, n, TRUE, randompad );
	mp_modexp( (unitptr)outbuf, (unitptr)inbuf, e, n );	/* RSA encrypt */

	/* write out header record to outfile ... */

	ctb = CTB_PKE;				/*	PKE is Public Key Encryption */
	PKElength = KEYFRAGSIZE + countbytes( (unitptr)outbuf ) + 2;
	fwrite( &ctb, 1, 1, g );	/*	write RSA msg CTB */

	/* Change PKElength to external byte order: */

	convert( PKElength ); 
	fwrite( &PKElength, 1, sizeof( PKElength ), g );	/* write length */

	writekeyID( n, g );	/* write msg prefix fragment of modulus n */

	/* convert RSA ciphertext block via reg2mpi and write to file */

	write_mpi( (unitptr)outbuf, g, FALSE );

	burn(inbuf);	/* burn sensitive data on stack */
	burn(outbuf);	/* burn sensitive data on stack */

	/**	Finished with RSA block containing BassOmatic key. */

	/* Now compress the plaintext and encrypt it with BassOmatic... */
	squish_and_bass_file( basskey, ckp_length-1, f, g );

	burn(basskey);	/* burn sensitive data on stack */

	fclose(g);
	fclose(f);

	return(0);
}	/* encryptfile */


/*======================================================================*/
int make_literal(char *infile, char *outfile)
{	/*	An awful lot of hassle to go thru just to prepend 1 lousy byte.
		Prepends a CTB_LITERAL prefix byte to a file.
	*/
	byte ctb;	/* Cipher Type Byte */
	FILE *f;
	FILE *g;

	if (verbose)
		fprintf(stderr,"\nInput plaintext file: %s, Output plaintext file: %s\n",
		infile,outfile);

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(infile,"rb")) == NULL)
	{	fprintf(stderr,"\n\aCan't open input plaintext file '%s'\n",infile);
		return(-1);
	}

	/* 	open file g for write, in binary (not text) mode... */
	if ((g = fopen( outfile, "wb" )) == NULL)
	{	fprintf(stderr, "\n\aCan't create plaintext file '%s'\n", outfile );
		goto err1;
	}

	ctb = CTB_LITERAL;	/* prepend this byte prefix to message */
	fwrite( &ctb, 1, 1, g );	/*	write LITERAL CTB */
	/* No CTB packet length specified means indefinite length. */

	copyfile( f, g, -1UL );	/* copy rest of literal plaintext file */

	fclose(g);
	fclose(f);
	return(0);	/* normal return */

err1:
	fclose(f);
	return(-1);	/* error return */

}	/* make_literal */


/*======================================================================*/
int strip_literal(char *infile, char *outfile)
{	/*	A lot of hassle to go thru just to strip off 1 lousy prefix byte. 
		Strips off the CTB_LITERAL prefix byte from a file.
	*/
	byte ctb;	/* Cipher Type Byte */
	FILE *f;
	FILE *g;
	word32 LITlength = 0;

	if (verbose)
		fprintf(stderr,"\nInput plaintext file: %s, output plaintext file: %s\n",
		infile,outfile);

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(infile,"rb")) == NULL)
	{	fprintf(stderr,"\n\aCan't open input plaintext file '%s'\n",infile);
		return(-1);
	}

	fread(&ctb,1,1,f);	/* read Cipher Type Byte */

	if (!is_ctb(ctb) || !is_ctb_type(ctb,CTB_LITERAL_TYPE))
	{	fprintf(stderr,"\n\a'%s' is not a literal plaintext file.\n",infile);
		fclose(f);
		return(-1);
	}

	LITlength = getpastlength(ctb, f); /* read packet length */

	if (file_exists( outfile ))
	{	fprintf(stderr, "\n\aOutput file '%s' already exists.  Overwrite (y/N)? ", outfile );
		if (! getyesno( 'n' ))
			goto err1;		/* user said don't do it - abort operation */
	}

	/* 	open file g for write, in binary (not text) mode... */

	if ((g = fopen( outfile, "wb" )) == NULL)
	{	fprintf(stderr, "\n\aCan't create plaintext file '%s'\n", outfile );
		goto err1;
	}

	copyfile( f, g, LITlength );	/* copy rest of literal plaintext file */

	fclose(g);
	fclose(f);
	return(0);	/* normal return */

err1:
	fclose(f);
	return(-1);	/* error return */

}	/* strip_literal */


/*======================================================================*/


int decryptfile(char *infile, char *outfile)
{
	byte ctb;	/* Cipher Type Byte */
	byte ctbCKE; /* Cipher Type Byte */
	FILE *f;
	FILE *g;
	int count, status;
	word32 PKElength, CKElength;
	unit n[MAX_UNIT_PRECISION], e[MAX_UNIT_PRECISION], d[MAX_UNIT_PRECISION];
	unit p[MAX_UNIT_PRECISION], q[MAX_UNIT_PRECISION], u[MAX_UNIT_PRECISION];
	byte inbuf[MAX_BYTE_PRECISION];
	byte outbuf[MAX_BYTE_PRECISION];
	byte keyID[KEYFRAGSIZE];
	word32 tstamp; byte *timestamp = (byte *) &tstamp;		/* key certificate timestamp */
	byte userid[256];

	set_precision(MAX_UNIT_PRECISION);	/* safest opening assumption */

	if (verbose)
		fprintf(stderr,"\nCiphertext file: %s, plaintext file: %s\n",
		infile,outfile);

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(infile,"rb")) == NULL)
	{	fprintf(stderr,"\n\aCan't open ciphertext file '%s'\n",infile);
		return(-1);
	}

	fread(&ctb,1,1,f);	/* read Cipher Type Byte */
	if (!is_ctb(ctb))
	{	fprintf(stderr,"\n\a'%s' is not a cipher file.\n",infile);
		fclose(f);
		return(-1);
	}

	/* PKE is Public Key Encryption */
	if (!is_ctb_type(ctb,CTB_PKE_TYPE))
	{	fprintf(stderr,"\n\a'%s' is not enciphered with a public key.\n",infile);
		fclose(f);
		return(-1);
	}

	PKElength = getpastlength(ctb, f); /* read packet length */

	fread(keyID,1,KEYFRAGSIZE,f); /* read key ID */
	/* Use keyID prefix to look up key. */

	/*	Get and validate secret key from a key file: */
	if (getsecretkey(keyID, timestamp, userid, n, e, d, p, q, u) < 0)
	{	fclose(f);
		return(-1);
	}

	/*	Note that RSA key must be at least big enough to encipher a
		complete conventional key packet in a single RSA block. */

	/*==================================================================*/
	/* read ciphertext block, converting to internal format: */
	read_mpi((unitptr)inbuf, f, FALSE, FALSE);

	fprintf(stderr,"Just a moment-- ");	/* RSA will take a while. */

	rsa_decrypt((unitptr)outbuf, (unitptr)inbuf, d, p, q, u);

	if ((count = postunblock(outbuf, (unitptr)outbuf, n, TRUE, TRUE)) < 0)
	{	fprintf(stderr,"\n\aBad RSA decrypt: checksum or pad error during unblocking.\n");
		fclose(f);
		return(-1);
	}

	fputc('.',stderr);	/* Signal RSA completion. */

	/* outbuf should contain random BassOmatic key packet */
	/*==================================================================*/
	/* Look at nested stuff within RSA block... */

	ctb = outbuf[0];	/* get nested CTB, should be CTB_CONKEY */

	if (!is_ctb_type(ctb,CTB_CONKEY_TYPE))
	{ 	fprintf(stderr,"\aNested info is not a conventional key packet.\n");
		goto err1;
	}

	/*	Test the Conventional Key Packet for supported algorithms.
		(currently, just the BassOmatic is supported) */

	if ( outbuf[2] != BASS_ALGORITHM_BYTE )
	{	fprintf(stderr,"\a\nUnrecognized conventional encryption algorithm.\n");
		goto err1;
	}

	if (file_exists( outfile ))
	{	fprintf(stderr, "\n\aOutput file '%s' already exists.  Overwrite (y/N)? ", outfile );
		if (! getyesno( 'n' ))
			goto err1;		/* user said don't do it - abort operation */
	}

	/* 	open file g for write, in binary (not text) mode... */
	if ((g = fopen( outfile, "wb" )) == NULL)
	{	fprintf(stderr, "\n\aCan't create plaintext file '%s'\n", outfile );
		goto err1;
	}

	fread(&ctbCKE,1,1,f);	/* read Cipher Type Byte, should be CTB_CKE */
	if (ctbCKE != CTB_CKE)
	{	/* Should never get here. */
		fprintf(stderr,"\a\nBad or missing CTB_CKE byte.\n");
		goto err1;	/* Abandon ship! */
	}

	CKElength = getpastlength(ctbCKE, f); /* read packet length */

	status = bass_file( outbuf+3, count-3, TRUE, f, g );	/* Decrypt ciphertext file */

	fclose(g);
	fclose(f);
	burn(inbuf);	/* burn sensitive data on stack */
	burn(outbuf);	/* burn sensitive data on stack */
	mp_burn(d);	/* burn sensitive data on stack */
	mp_burn(p);	/* burn sensitive data on stack */
	mp_burn(q);	/* burn sensitive data on stack */
	mp_burn(u);	/* burn sensitive data on stack */
	if (status < 0)	/* if bass_file failed, then error return */
		return(status);
	return(1);	/* always indicate output file has nested stuff in it. */

err1:
	fclose(f);
	burn(inbuf);	/* burn sensitive data on stack */
	burn(outbuf);	/* burn sensitive data on stack */
	mp_burn(d);	/* burn sensitive data on stack */
	mp_burn(p);	/* burn sensitive data on stack */
	mp_burn(q);	/* burn sensitive data on stack */
	mp_burn(u);	/* burn sensitive data on stack */
	return(-1);	/* error return */

}	/* decryptfile */



int bass_decryptfile(char *infile, char *outfile)
{
	byte ctb;	/* Cipher Type Byte */
	FILE *f;
	FILE *g;
	word32 CKElength;
	byte basskey[256];
	int basskeylen;	/* must get no bigger than sizeof(basskey)-2 */
	int status;

	if (verbose)
		fprintf(stderr,"\nCiphertext file: %s, plaintext file: %s\n",
		infile,outfile);

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(infile,"rb")) == NULL)
	{	fprintf(stderr,"\n\aCan't open ciphertext file '%s'\n",infile);
		return(-1);
	}

	fread(&ctb,1,1,f);	/* read Cipher Type Byte, should be CTB_CKE */

	if (!is_ctb(ctb) || !is_ctb_type(ctb,CTB_CKE_TYPE))
	{	/* Should never get here. */
		fprintf(stderr,"\a\nBad or missing CTB_CKE byte.\n");
		goto err1;	/* Abandon ship! */
	}

	CKElength = getpastlength(ctb, f); /* read packet length */
	/* The packet length is ignored.  Assume it's huge. */

	if (file_exists( outfile ))
	{	fprintf(stderr, "\n\aOutput file '%s' already exists.  Overwrite (y/N)? ", outfile );
		if (! getyesno( 'n' ))
			goto err1;		/* user said don't do it - abort operation */
	}

	/* 	open file g for write, in binary (not text) mode... */
	if ((g = fopen( outfile, "wb" )) == NULL)
	{	fprintf(stderr, "\n\aCan't create plaintext file '%s'\n", outfile );
		goto err1;
	}

	/* Get BassOmatic password with leading BassOmatic control byte: */
	/* Default is Military grade BassOmatic key control byte */
	if (getpassword(basskey,NOECHO1,0x1f) <= 0)
		return(-1);

	basskeylen = strlen(basskey);

	status = bass_file( basskey, basskeylen, TRUE, f, g ); /* decrypt file */

	burn(basskey);	/* burn sensitive data on stack */

	fclose(g);
	fclose(f);

	if (status < 0)	/* if bass_file failed, then complain */
	{	fprintf(stderr,"\n\aError:  Bad pass phrase. ");
		remove(outfile);	/* throw away our mistake */
		return(status);		/* error return */
	}
	return(1);	/* always indicate output file has nested stuff in it. */

err1:
	fclose(f);
	return(-1);	/* error return */

}	/* bass_decryptfile */



int decompress_file(char *infile, char *outfile)
{
	byte ctb;
	FILE *f;
	FILE *g;
	word32 compress_pkt_length;
	extern void lzhDecode( FILE *, FILE * );
	if (verbose) fprintf(stderr, "Decompressing plaintext..." );

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(infile,"rb")) == NULL)
	{	fprintf(stderr,"\n\aCan't open compressed file '%s'\n",infile);
		return(-1);
	}

	fread(&ctb,1,1,f);	/* read and skip over Cipher Type Byte */
	if (!is_ctb_type( ctb, CTB_COMPRESSED_TYPE ))
	{	/* Shouldn't get here, or why were we called to begin with? */
		fprintf(stderr,"\a\nBad or missing CTB_COMPRESSED byte.\n");
		goto err1;	/* Abandon ship! */
	}

	compress_pkt_length = getpastlength(ctb, f); /* read packet length */
	/* The packet length is ignored.  Assume it's huge. */

	fread(&ctb,1,1,f);	/* read and skip over compression algorithm byte */
	if (ctb != LZH_ALGORITHM_BYTE)
	{	/* We only know one compression algorithm */
		fprintf(stderr,"\a\nUnrecognized compression algorithm.\n");
		goto err1;	/* Abandon ship! */
	}

	/* 	open file g for write, in binary (not text) mode... */
	if ((g = fopen( outfile, "wb" )) == NULL)
	{	fprintf(stderr, "\n\aCan't create decompressed file '%s'\n", outfile );
		goto err1;
	}

	lzhDecode( f, g );
	if (verbose) fprintf(stderr, "done.  " );
	fclose(g);
	fclose(f);
	return(1);	/* always indicate output file has nested stuff in it. */
err1:
	fclose(f);
	return(-1);	/* error return */

}	/* decompress_file */



int view_keyring(char *mcguffin, char *ringfile)
/*	Lists all entries in keyring that have mcguffin string in userid.
	mcguffin is a null-terminated C string.
*/
{	FILE *f;
	long file_position,fp;
	byte ctb;
	int status;
	unit n[MAX_UNIT_PRECISION], e[MAX_UNIT_PRECISION];
	byte keyID[KEYFRAGSIZE];
	byte userid[256];		/* key certificate userid */
	word32 tstamp;
	byte *timestamp = (byte *) &tstamp;		/* key certificate timestamp */
	int keycounter = 0;

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(ringfile,"rb")) == NULL)
	{	fprintf(stderr,"\n\aCan't open key ring file '%s'\n",ringfile);
		return(-1);
	}

/*	Here's a good format for display of key or signature certificates:
Type bits/keyID   Date     User ID
pub  990/xxxxxx dd-mmm-yy  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sec  990/xxxxxx dd-mmm-yy  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sig  990/xxxxxx dd-mmm-yy  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
com  990/xxxxxx dd-mmm-yy  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
*/

	fprintf(stderr,"\nKey ring: '%s'",ringfile);
	if (strlen(mcguffin) > 0)
		fprintf(stderr,", looking for user ID \"%s\".",mcguffin);
	fprintf(stderr,"\nType bits/keyID   Date     User ID\n");
	do
	{
		status = readkeypacket(f,FALSE,&ctb,timestamp,userid,n,e,
				NULL,NULL,NULL,NULL);
		/* Note that readkeypacket has called set_precision */
		if (status== -1 ) break;	/* eof reached */
		if (status < 0)
		{	fprintf(stderr,"\n\aCould not read key from file '%s'.\n",
				ringfile);
			fclose(f);	/* close key file */
			return(-1);
		}

		if (!is_ctb_type(ctb,CTB_CERT_PUBKEY_TYPE)
		&&  !is_ctb_type(ctb,CTB_CERT_SECKEY_TYPE))
		{
			fprintf(stderr,"\n\aError in file '%s'.  Not a key certificate.\n",
				ringfile);
			return(-1);
		}

		keycounter++;

		extract_keyID(keyID, n);
		PascalToC(userid);

		if (strcontains(userid,mcguffin))
		{
			if (is_ctb_type(ctb,CTB_CERT_PUBKEY_TYPE))
			{
				if (testeq(e,0))	/* e==0 means key compromised */
					fprintf(stderr,"com ");	/* "key compromised" certificate */
				else
					fprintf(stderr,"pub ");	/* public key certificate */
			}
			else if (is_ctb_type(ctb,CTB_CERT_SECKEY_TYPE))
				fprintf(stderr,"sec ");		/* secret key certificate */
			else
				fprintf(stderr,"??? ");		/* otherwise, who knows? */

			fprintf(stderr,"%4d/",countbits(n));
			showkeyID(keyID);
			fputc(' ',stderr);
			show_date((long *)timestamp);
			fprintf(stderr,"  ");
			fprintf(stderr,userid);
			fputc('\n',stderr);
		}	/* if it has mcguffin */
	} while (status >= 0);

	fclose(f);	/* close key file */
	fprintf(stderr,"%d key(s) examined. ",keycounter);

	return(0);	/* normal return */

}	/* view_keyring */



int remove_from_keyring(byte *keyID, char *mcguffin, char *ringfile)
/*	Remove the first entry in key ring that has mcguffin string in userid.
	Or it removes the first matching keyID from the ring.
	A non-NULL keyID takes precedence over a mcguffin specifier.
	mcguffin is a null-terminated C string.
*/
{
	FILE *f;
	FILE *g;
	long file_position,fp,after_key;
	int packetlength=0;
	byte ctb;
	int status;
	unit n[MAX_UNIT_PRECISION], e[MAX_UNIT_PRECISION];
	byte userid[256];		/* key certificate userid */
	word32 tstamp; byte *timestamp = (byte *) &tstamp;		/* key certificate timestamp */

	default_extension(ringfile,PUB_EXTENSION);

	if ((keyID==NULL) && (strlen(mcguffin)==0))
		return(-1); /* error, null mcguffin will match everything */

	strcpy(userid,mcguffin);

	fprintf(stderr,"\nRemoving from key ring: '%s'",ringfile);
	if (strlen(mcguffin) > 0)
		fprintf(stderr,", userid \"%s\".\n",mcguffin);

	status = getpublickey(TRUE, TRUE, ringfile, &fp, &packetlength, NULL, timestamp, userid, n, e);
	if (status < 0)
	{	fprintf(stderr,"\n\aKey not found in key ring '%s'.\n",ringfile);
		return(0);	/* normal return */
	}
	after_key = fp + packetlength;

	if (testeq(e,0))	/* This is a key compromise certificate. */
	{	/* Wish there was a more elegant way to handle this... */
		fprintf(stderr,"\n\aWARNING: This is a \"key compromised\" certificate.");
		fprintf(stderr,"\nIt should not be removed from the key ring!\n");
		if (keyID != NULL) /* Decision requires human confirmation. */
			return(-1);
	}

	if (keyID==NULL)	/* Human confirmation is required. */
	{	/* Supposedly the key was fully displayed by getpublickey */
		fprintf(stderr,"\nAre you sure you want this key removed (y/N)? ");
		if (!getyesno('n'))
			return(-1);	/* user said "no" */
	}

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(ringfile,"rb")) == NULL)
	{	fprintf(stderr,"\n\aCan't open key ring file '%s'\n",ringfile);
		return(-1);
	}

	remove(SCRATCH_KEYRING_FILENAME);
	/* open file g for writing, in binary (not text) mode...*/
	if ((g = fopen(SCRATCH_KEYRING_FILENAME,"wb")) == NULL)
	{	fclose(f);
		return(-1);
	}
	rewind(f);
	copyfile(f,g,fp);	/* copy file f to g up to position fp */
	fseek(f,after_key,SEEK_SET); /* reposition file to after key */
	copyfile(f,g,-1UL);	/* copy rest of file from file f to g */
	fclose(g);	/* close scratch file */
	fclose(f);	/* close key file */
	remove(ringfile); /* dangerous.  sure hope rename works... */
	rename(SCRATCH_KEYRING_FILENAME,ringfile);
	fprintf(stderr,"\nKey removed from key ring. ");

	return(0);	/* normal return */

}	/* remove_from_keyring */



int addto_keyring(char *keyfile, char *ringfile)
/*	Adds (prepends) key file to key ring file */
{	FILE *f;
	FILE *g;
	long file_position,fp;
	int pktlen;	/* unused, just to satisfy getpublickey */
	byte ctb;
	int status;
	unit n[MAX_UNIT_PRECISION], e[MAX_UNIT_PRECISION];
	byte keyID[KEYFRAGSIZE];
	byte userid[256];		/* key certificate userid */
	word32 tstamp; byte *timestamp = (byte *) &tstamp;		/* key certificate timestamp */
	boolean keycompromised;

	if (strcontains(ringfile,SEC_EXTENSION))
		force_extension(SCRATCH_KEYRING_FILENAME,SEC_EXTENSION);
	else
		force_extension(SCRATCH_KEYRING_FILENAME,PUB_EXTENSION);

	/* open file f for read, in binary (not text) mode...*/
	if ((f = fopen(keyfile,"rb")) == NULL)
	{	fprintf(stderr,"\n\aCan't open key file '%s'\n",keyfile);
		return(-1);
	}

	/*	Check to see if the keyID is already in key ring before we add it in. */

	file_position = ftell(f);
	status = readkeypacket(f,FALSE,&ctb,timestamp,userid,n,e,
			NULL,NULL,NULL,NULL);
	/* Note that readkeypacket has called set_precision */
	if (status < 0)
	{	fprintf(stderr,"\n\aCould not read key from file '%s'.\n",
			keyfile);
		fclose(f);	/* close key file */
		return(-1);
	}

	if (!is_ctb_type(ctb,CTB_CERT_PUBKEY_TYPE)
		&& !is_ctb_type(ctb,CTB_CERT_SECKEY_TYPE))
	{	fprintf(stderr,"\n\aError in file '%s'.  Not a key certificate.\n",
			keyfile);
		return(-1);
	}

	extract_keyID(keyID, n);	/* from keyfile, not ringfile */

	if (!file_exists(ringfile))
	{	/* ringfile does not exist.  Can it be created? */
		/* open file g for writing, in binary (not text) mode...*/
		g = fopen(ringfile,"wb");
		if (g==NULL)
		{	fprintf(stderr,"\n\aKey ring file '%s' cannot be created.\n",ringfile);
			fclose(f);
			return(-1);
		}
		fclose(g);
	}

	/* See if we are adding a "secret key compromised" certificate: */
	keycompromised = testeq(e,0);

	/*	If this is a key compromise certificate, maybe we should 
		remove the real public key from the key ring if it's on the 
		key ring before adding the key compromise certificate.
		Probably not, though, because the prepended key compromise 
		certificate will take search order precedence.
		And it may be nice to keep the original public key certificate
		around for its timestamp, to check old signatures.
		It should not be possible to later add the same public key to
		the ring again if the key compromise certificate was there first.

		These tests for duplicates should have to be applied for all
		the keys being added to the ring, in case the added key file
		is itself a multikey ring.  Fix this later.
	*/

	/*	Check for duplicate key in key ring: */
	if (getpublickey(TRUE, TRUE, ringfile, &fp, &pktlen, keyID, timestamp, userid, n, e) >= 0)
	{	fprintf(stderr,"\n\aKey already included in key ring '%s'.\n",ringfile);
		if (!keycompromised) /* allows duplicate if key compromised */
		{	fclose(f);	/* close key file */
			return(0);	/* normal return */
		}
	}

	if (keycompromised)
		fprintf(stderr,"\nAdding \"key compromise\" certificate '%s' to key ring '%s'.\n",
			keyfile,ringfile);
	else
		fprintf(stderr,"\nAdding key certificate '%s' to key ring '%s'.\n",keyfile,ringfile);

	/*	The key is prepended to the ring to give it search precedence 
		over other keys with that same userid. */

	fseek(f,file_position,SEEK_SET); /* reposition file to key */

	remove(SCRATCH_KEYRING_FILENAME);
	/* open file g for writing, in binary (not text) mode...*/
	if ((g = fopen(SCRATCH_KEYRING_FILENAME,"wb")) == NULL)
	{	fclose(f);
		return(-1);
	}
	copyfile(f,g,-1UL);	/* copy rest of file from file f to g */
	fclose(f);


	/* open file f for reading, in binary (not text) mode...*/
	if ((f = fopen(ringfile,"rb")) != NULL)
	{	copyfile(f,g,-1UL);	/* copy rest of file from file f to g */
		fclose(f);
	}
	fclose(g);

	remove(ringfile); /* dangerous.  sure hope rename works... */
	rename(SCRATCH_KEYRING_FILENAME,ringfile);

	return(0);	/* normal return */

}	/* addto_keyring */


/*======================================================================*/



int dokeygen(char *keyfile, char *numstr, char *numstr2)
/*	Do an RSA key pair generation, and write them out to a pair of files.	
	The keyfile filename string must not have a file extension.
	numstr is a decimal string, the desired bitcount for the modulus n.
	numstr2 is a decimal string, the desired bitcount for the exponent e.
*/
{	unit n[MAX_UNIT_PRECISION], e[MAX_UNIT_PRECISION], d[MAX_UNIT_PRECISION],
	     p[MAX_UNIT_PRECISION], q[MAX_UNIT_PRECISION], u[MAX_UNIT_PRECISION];
	char fname[64];
	char ringfile[64];
	byte iv[256]; /* for BassOmatic CFB mode, to protect RSA secret key */
	byte userid[256];
	short keybits,ebits,i;
	word32 tstamp; byte *timestamp = (byte *) &tstamp;		/* key certificate timestamp */
	boolean hidekey;	/* TRUE iff secret key is encrypted */

	strcpy(fname,keyfile); 
	if (strlen(fname)==0)
	{	fprintf(stderr,"\nKey file name is required for RSA key pair: ");
		getstring(fname,sizeof(fname)-4,TRUE);
	}

	if (strlen(numstr)==0)
	{	fprintf(stderr,"\nPick your RSA key size: "
			"\n	1)	288 bits- Casual grade, fast but less secure"
			"\n	2)	512 bits- Commercial grade, medium speed, good security"
			"\n	3)	992 bits- Military grade, very slow, highest security"
			"\nChoose 1, 2, or 3, or enter desired number of bits: ");
		numstr = userid;	/* use userid buffer as scratchpad */
		getstring(numstr,5,TRUE);	/* echo keyboard */
	}

	keybits = 0;
	while ((*numstr>='0') && (*numstr<='9')) 
		keybits = keybits*10 + (*numstr++ - '0');

	/* Standard default key sizes: */
	if (keybits==1) keybits=286;	/* Casual grade */
	if (keybits==2) keybits=510;	/* Commercial grade */
	if (keybits==3) keybits=990;	/* Military grade */

	/* minimum RSA keysize for BassOmatic bootstrap: */
	if (keybits<286) keybits=286;

	ebits = 0;	/* number of bits in e */
	while ((*numstr2>='0') && (*numstr2<='9')) 
		ebits = ebits*10 + (*numstr2++ - '0');

	fprintf(stderr,"\nGenerating an RSA key with a %d-bit modulus... ",keybits);

	fprintf(stderr,"\nEnter a user ID for your public key (your name): ");
	getstring(userid,255,TRUE);	/* echo keyboard input */
	CToPascal(userid);	/* convert to length-prefixed string */

	{	char passphrase[256];
		fprintf(stderr,"\nYou need a pass phrase to protect your RSA secret key. ");
		hidekey = (getpassword(passphrase,2,0x0f) > 0);
		/* init CFB BassOmatic key */
		if (hidekey)
		{	fill0(iv,256);	/* define initialization vector IV as 0 */
			if ( initcfb(iv,passphrase,string_length(passphrase),FALSE) < 0 )
				return(-1);
			burn(passphrase);	/* burn sensitive data on stack */
		}
	}

	fprintf(stderr,"\nNote that key generation is a VERY lengthy process.\n");

	if (keygen(n,e,d,p,q,u,keybits,ebits) < 0)
	{	fprintf(stderr,"\n\aKeygen failed!\n");
		return(-1);	/* error return */
	}

	if (verbose)
	{
		fprintf(stderr,"Key ID ");
		showkeyID2(n); fputc('\n',stderr);

		mp_display(" modulus n = ",n);
		mp_display("exponent e = ",e);

		mp_display("exponent d = ",d);
		mp_display("   prime p = ",p);
		mp_display("   prime q = ",q);
		mp_display(" inverse u = ",u);
	}

	get_timestamp(timestamp);	/* Timestamp when key was generated */

	fputc('\a',stderr);  /* sound the bell when done with lengthy process */

	force_extension(fname,SEC_EXTENSION);
	writekeyfile(fname,hidekey,timestamp,userid,n,e,d,p,q,u); 
	force_extension(fname,PUB_EXTENSION);
	writekeyfile(fname,FALSE,timestamp,userid,n,e,NULL,NULL,NULL,NULL); 
	
	if (hidekey)	/* done with Bassomatic to protect RSA secret key */
		closebass();

	mp_burn(d);	/* burn sensitive data on stack */
	mp_burn(p);	/* burn sensitive data on stack */
	mp_burn(q);	/* burn sensitive data on stack */
	mp_burn(u);	/* burn sensitive data on stack */
	mp_burn(e);	/* burn sensitive data on stack */
	mp_burn(n);	/* burn sensitive data on stack */
	burn(iv);	/* burn sensitive data on stack */

	force_extension(fname,PUB_EXTENSION);
	buildfilename(ringfile,PUBLIC_KEYRING_FILENAME);
	fprintf(stderr,"\nAdd public key to key ring '%s' (y/N)? ",ringfile);
	if (getyesno('n'))
		addto_keyring(fname,ringfile);
	force_extension(fname,SEC_EXTENSION);
	buildfilename(ringfile,SECRET_KEYRING_FILENAME);
	fprintf(stderr,"Add secret key to key ring '%s' (y/N)? ",ringfile);
	if (getyesno('n'))
		addto_keyring(fname,ringfile);

	/*	Force initialization of cryptographically strong pseudorandom
		number generator seed file for later use...
	*/
	strong_pseudorandom(iv,1);

	return(0);	/* normal return */
}	/* dokeygen */


/*======================================================================*/


void main(int argc, char *argv[])
{	char keyfile[64], plainfile[64], cipherfile[64], ringfile[64], tempfile[64];
	int status,i;
	boolean nestflag = FALSE;
	boolean uu_emit = FALSE;
	boolean wipeflag = FALSE;
	byte ctb;
	byte header[6];	/* used to classify file type at the end. */
	char mcguffin[256];	/* userid search tag */

#ifdef	DEBUG1
	verbose = TRUE;
#endif

	fprintf(stderr,"Pretty Good Privacy 1.0 - RSA public key cryptography for the masses.\n"
		"(c) Copyright 1990 Philip Zimmermann, Phil's Pretty Good Software.  5 Jun 91\n");

	if (argc <= 1)
	{	fprintf(stderr,
		"\nFor details on free licensing and distribution, see the PGP User's Guide."
		"\nFor other cryptography products and custom development services, contact:"
		"\nPhilip Zimmermann, 3021 11th St, Boulder CO 80304 USA, phone (303)444-4541"
		);
		goto usage;
	}

	/* Make sure arguments will fit into filename strings: */
	for (i = 1; i <= argc; i++)
	{
		if (strlen(argv[i]) >= sizeof(cipherfile)-4)
		{
			fprintf(stderr, "\aInvalid filename: [%s] too long\n", argv[i] );
			goto user_error;
		}
	}

	if (argv[1][0] == '-')
	{
		if (strhas(argv[1],'l'))
			verbose = TRUE;

		nestflag = strhas(argv[1],'n');

		uu_emit = strhas(argv[1],'u');

		wipeflag = strhas(argv[1],'w');

		/*-------------------------------------------------------*/
		if ( (argc >= 3)
		&&  strhasany(argv[1],"sS")	&&  strhasany(argv[1],"eE") )
		{	/* Sign AND encrypt file */
			/* Arguments: plainfile, her_userid, your_userid, cipherfile */
			boolean separate_signature = FALSE;

			strcpy( plainfile, argv[2] );

			if (argc>=6)	/* default signature file extension */
			{	strcpy( cipherfile, argv[5] );
				default_extension( cipherfile, CTX_EXTENSION );
			}
			else
			{	/* Default the signature file name */
				strcpy( cipherfile, plainfile );
				/* ...but replace file extension: */
				force_extension( cipherfile, CTX_EXTENSION );
			}

			if (strcmp( plainfile, cipherfile ) == 0)
			{	fprintf(stderr, "\aFile [%s] must be specified just once.\n", plainfile );
				goto user_error;	/* same filenames for both files */
			}

			if (argc>=5)
			{	strcpy( mcguffin, argv[4] );	/* Userid of signer */
				translate_spaces( mcguffin );	/* change all '_' to ' ' */
			}
			else
			{	fprintf(stderr, "\nEnter userid to look up your secret key for signature: ");
				getstring( mcguffin, 255, TRUE );	/* echo keyboard */
			}

			if (nestflag)	/* user thinks this file has nested info */
			{	get_header_info_from_file( plainfile, &ctb, 1);
				if (!legal_ctb(ctb))
				{	nestflag = FALSE;
					fprintf(stderr,"\n\aNo nestable data in plaintext file '%s'.\n",plainfile);
				}
			}

			status = signfile( nestflag, separate_signature,
					 mcguffin, plainfile, SCRATCH_CTX_FILENAME );

			if (status < 0)		/* signfile failed */
			{	fprintf(stderr, "\aSignature error\n" );
				goto user_error;
			}

			if (wipeflag)
			{	wipefile(plainfile); /* destroy every trace of plaintext */
				remove(plainfile);
				fprintf(stderr,"\nFile %s wiped and deleted. ",plainfile);
			}

			if (argc>=4)
			{	strcpy( mcguffin, argv[3] );	/* Userid of recipient */
				translate_spaces( mcguffin );	/* change all '_' to ' ' */
			}
			else
			{	fprintf(stderr, "\nEnter userid to look up recipient's public key: ");
				getstring( mcguffin, 255, TRUE );	/* echo keyboard */
			}

			/* Indicate that encrypted data has nested signature: */

			status = encryptfile( TRUE, mcguffin, SCRATCH_CTX_FILENAME, cipherfile );

			wipefile( SCRATCH_CTX_FILENAME );
			remove( SCRATCH_CTX_FILENAME );
			
			if (status < 0)
			{	fprintf(stderr, "\aEncryption error\n" );
				goto user_error;
			}

			if (uu_emit)
			{	status = uue_file(cipherfile, SCRATCH_CTX_FILENAME);
				remove(cipherfile); /* dangerous.  sure hope rename works... */
				rename(SCRATCH_CTX_FILENAME, cipherfile);
			}

			if (!verbose)	/* if other filename messages were supressed */
				fprintf(stderr,"\nCiphertext file: %s ", cipherfile);

			exit(0);
		}	/* Sign AND encrypt file */


		/*-------------------------------------------------------*/
		if ( (argc >= 3) && strhasany(argv[1],"sS") )
		{	/*	Sign file
				Arguments: plaintextfile, your_userid, signedtextfile
				Two kinds of signature:  full signature certificate,
				or just an RSA-signed message digest.
			*/

			boolean separate_signature = FALSE;

			separate_signature = strhas( argv[1], 'b' );

			strcpy( plainfile, argv[2] );

			if (argc>=5)	/* default signature file extension */
			{	strcpy( cipherfile, argv[4] );
				default_extension( cipherfile, CTX_EXTENSION );
			}
			else
			{	/* Default the signature file name */
				strcpy( cipherfile, plainfile );
				/* ...but replace file extension: */
				force_extension( cipherfile, CTX_EXTENSION );
			}

			if (strcmp( plainfile, cipherfile ) == 0)
			{	fprintf(stderr, "\aFile [%s] must be specified just once.\n", plainfile );
				goto user_error;	/* same filenames for both files */
			}

			if (argc>=4)
			{	strcpy( mcguffin, argv[3] );	/* Userid of signer */
				translate_spaces( mcguffin );	/* change all '_' to ' ' */
			}
			else
			{	fprintf(stderr, "\nEnter userid to look up your secret key for signature: ");
				getstring( mcguffin, 255, TRUE );	/* echo keyboard */
			}

			if (nestflag)	/* user thinks this file has nested info */
			{	get_header_info_from_file( plainfile, &ctb, 1);
				if (!legal_ctb(ctb))
				{	nestflag = FALSE;
					fprintf(stderr,"\n\aNo nestable data in plaintext file '%s'.\n",plainfile);
				}
			}

			status = signfile( nestflag, separate_signature,
					 mcguffin, plainfile, cipherfile );

			if (status < 0)		/* signfile failed */
			{	fprintf(stderr, "\aSignature error\n" );
				goto user_error;
			}

			if (uu_emit)
			{	status = uue_file(cipherfile, SCRATCH_CTX_FILENAME);
				remove(cipherfile); /* dangerous.  sure hope rename works... */
				rename(SCRATCH_CTX_FILENAME, cipherfile);
			}

			if (!verbose)	/* if other filename messages were supressed */
				fprintf(stderr,"\nSignature file: %s ", cipherfile);

			exit(0);
		}	/* Sign file */


		/*-------------------------------------------------------*/
		if ( (argc >= 3) && strhasany(argv[1],"eE") )
		{	/*	Encrypt file
				Arguments: plaintextfile, her_userid, ciphertextfile
			*/

			strcpy( plainfile, argv[2] );

			if (argc >= 5)	/* default cipher file extension */
			{	strcpy( cipherfile, argv[4] );
				default_extension( cipherfile, CTX_EXTENSION );
			}
			else
			{	/* Default the cipherfile name */
				strcpy( cipherfile, plainfile );
				force_extension( cipherfile, CTX_EXTENSION );
			}

			if (strcmp( plainfile, cipherfile) == 0)
			{	fprintf(stderr, "\aFile [%s] must be specified just once.\n", plainfile );
				goto user_error;	/* same filenames for both files */
			}

			if (argc >= 4)
			{	strcpy( mcguffin, argv[3] );	/* Userid of recipient */
				translate_spaces( mcguffin );	/* change all '_' to ' ' */
			}
			else
			{	fprintf(stderr, "\nEnter userid to look up recipient's public key: ");
				getstring( mcguffin, 255, TRUE );	/* echo keyboard */
			}

			if (nestflag)	/* user thinks this file has nested info */
			{	get_header_info_from_file( plainfile, &ctb, 1);
				if (!legal_ctb(ctb))
				{	nestflag = FALSE;
					fprintf(stderr,"\n\aNo nestable data in plaintext file '%s'.\n",plainfile);
				}
			}

			if (!nestflag)
			{	/*	Prepend CTB_LITERAL byte to plaintext file. 
					--sure wish this pass could be optimized away. */
				strcpy( tempfile, plainfile );
				strcpy( plainfile, SCRATCH_PTX_FILENAME );
				status = make_literal( tempfile, plainfile );
			}
			status = encryptfile( nestflag, mcguffin, plainfile, cipherfile );

			if (!nestflag)
			{	wipefile( SCRATCH_PTX_FILENAME );
				remove( SCRATCH_PTX_FILENAME );
				strcpy( plainfile, tempfile );
			}

			if (status < 0)	/* encryptfile failed */
			{	fprintf(stderr, "\aEncryption error\n" );
				goto user_error;
			}

			if (wipeflag)
			{	wipefile(plainfile); /* destroy every trace of plaintext */
				remove(plainfile);
				fprintf(stderr,"\nFile %s wiped and deleted. ",plainfile);
			}

			if (uu_emit)
			{	status = uue_file(cipherfile, SCRATCH_CTX_FILENAME);
				remove(cipherfile); /* dangerous.  sure hope rename works... */
				rename(SCRATCH_CTX_FILENAME, cipherfile);
			}

			if (!verbose)	/* if other filename messages were supressed */
				fprintf(stderr,"\nCiphertext file: %s ", cipherfile);

			exit(0);
		}	/* Encrypt file */


		/*-------------------------------------------------------*/
		if ( (argc >= 3) && strhasany(argv[1],"cC") )
		{	/*	Encrypt file with BassOmatic only
				Arguments: plaintextfile, ciphertextfile
			*/

			strcpy( plainfile, argv[2] );

			if (argc >= 4)	/* default cipher file extension */
			{	strcpy( cipherfile, argv[3] );
				default_extension( cipherfile, CTX_EXTENSION );
			}
			else
			{	/* Default the cipherfile name */
				strcpy( cipherfile, plainfile );
				force_extension( cipherfile, CTX_EXTENSION );
			}

			if (strcmp( plainfile, cipherfile) == 0)
			{	fprintf(stderr, "\aFile [%s] must be specified just once.\n", plainfile );
				goto user_error;	/* same filenames for both files */
			}

			if (nestflag)	/* user thinks this file has nested info */
			{	get_header_info_from_file( plainfile, &ctb, 1);
				if (!legal_ctb(ctb))
				{	nestflag = FALSE;
					fprintf(stderr,"\n\aNo nestable data in plaintext file '%s'.\n",plainfile);
				}
			}

			if (!nestflag)
			{	/*	Prepend CTB_LITERAL byte to plaintext file. 
					--sure wish this pass could be optimized away. */
				strcpy( tempfile, plainfile );
				strcpy( plainfile, SCRATCH_PTX_FILENAME );
				status = make_literal( tempfile, plainfile );
			}

			status = bass_encryptfile( nestflag, plainfile, cipherfile );

			if (!nestflag)
			{	wipefile( SCRATCH_PTX_FILENAME );
				remove( SCRATCH_PTX_FILENAME );
				strcpy( plainfile, tempfile );
			}

			if (status < 0)	/* encryptfile failed */
			{	fprintf(stderr, "\aEncryption error\n" );
				goto user_error;
			}

			if (wipeflag)
			{	wipefile(plainfile); /* destroy every trace of plaintext */
				remove(plainfile);
				fprintf(stderr,"\nFile %s wiped and deleted. ",plainfile);
			}

			if (uu_emit)
			{	status = uue_file(cipherfile, SCRATCH_CTX_FILENAME);
				remove(cipherfile); /* dangerous.  sure hope rename works... */
				rename(SCRATCH_CTX_FILENAME, cipherfile);
			}

			if (!verbose)	/* if other filename messages were supressed */
				fprintf(stderr,"\nCiphertext file: %s ", cipherfile);

			exit(0);
		}	/* Encrypt file with BassOmatic only */


		/*-------------------------------------------------------*/
		if (argv[1][1] == 'k')
		{	/*	Key generation
				Arguments: keyfile, bitcount, bitcount
			*/
			char	keyfile[64], keybits[6], ebits[6];

			if (argc > 2)
				strcpy( keyfile, argv[2] );
			else
				strcpy( keyfile, "" );

			if (argc > 3)
				strncpy( keybits, argv[3], sizeof(keybits)-1 );
			else
				strcpy( keybits, "" );

			if (argc > 4)
				strncpy( ebits, argv[4], sizeof(ebits)-1 );
			else
				strcpy( ebits, "" );

			status = dokeygen( keyfile, keybits, ebits );

			if (status < 0)
			{	fprintf(stderr, "\aKeygen error. " );
				goto user_error;
			}
			exit(0);
		}	/* Key generation */

		/*-------------------------------------------------------*/
		if ((argc >= 3) && (argv[1][1] == 'a'))
		{	/*	Add key to key ring
				Arguments: keyfile, ringfile
			*/
			if (argc < 4)	/* default key ring filename */
				buildfilename( ringfile, PUBLIC_KEYRING_FILENAME );
			else
				strncpy( ringfile, argv[3], sizeof(ringfile)-1 );
			strncpy( keyfile, argv[2], sizeof(keyfile)-1 );

			strlwr( keyfile  );
			strlwr( ringfile );
			if (! file_exists( keyfile ))
				default_extension( keyfile, PUB_EXTENSION );

			if (strcontains( keyfile, SEC_EXTENSION ))
				force_extension( ringfile, SEC_EXTENSION );
			else
				force_extension( ringfile, PUB_EXTENSION );

			if (! file_exists( keyfile ))
			{	fprintf(stderr, "\n\aKey file '%s' does not exist.\n", keyfile );
				goto user_error;
			}

			status = addto_keyring( keyfile, ringfile );

			if (status < 0)
			{	fprintf(stderr, "\aKeyring add error. " );
				goto user_error;
			}
			exit(0);
		}	/* Add key to key ring */

		/*-------------------------------------------------------*/
		if ((argc >= 2)
		&& strhasany( argv[1], "vr" ) )
		{	/*	View or remove key ring entries, with userid match
				Arguments: userid, ringfile
			*/
			if (argc < 4)	/* default key ring filename */
				buildfilename( ringfile, PUBLIC_KEYRING_FILENAME );
			else
				strcpy( ringfile, argv[3] );

			strcpy( mcguffin, argv[2] );
			if (strcmp( mcguffin, "*" ) == 0)
				strcpy( mcguffin, "" );

			translate_spaces( mcguffin );	/* change all '_' to ' ' */

			if ((argc < 4) 
			&& (strcontains( argv[2], PUB_EXTENSION )
			||  strcontains( argv[2], SEC_EXTENSION )))
			{	strcpy( ringfile, argv[2] );
				strcpy( mcguffin, "" );
			}

			strlwr( ringfile );
			if (! file_exists( ringfile ))
				default_extension( ringfile, PUB_EXTENSION );

			if (strhas( argv[1], 'v' ))
				if (view_keyring( mcguffin, ringfile ) < 0)
				{ 	fprintf(stderr, "\aKeyring view error. " );
					goto user_error;
				}
			if (strhas( argv[1], 'r' ))
				if (remove_from_keyring( NULL, mcguffin, ringfile ) < 0)
				{	fprintf(stderr, "\aKeyring remove error. " );
					goto user_error;
				}
			exit(0);
		}	/* view or remove key ring entries, with userid match */
		/*-------------------------------------------------------*/
		
		fprintf(stderr, "\aUnrecognizable parameters. " );
		goto user_error;
	}	/* -options specified */


	/*---------------------------------------------------------*/
	/* no options specified */

	if (argc >= 2)
	{	/*	Decrypt file
			Arguments: ciphertextfile, plaintextfile
		*/
		strcpy( cipherfile, argv[1] ); 
		default_extension( cipherfile, CTX_EXTENSION );
 
		if (argc >= 3)
		{	strcpy( plainfile, argv[2] );
			default_extension( plainfile, "." );
		}
		else
		{	/* Default the plaintext file name */
			strcpy( plainfile, argv[1] );
			force_extension( plainfile, "." );
		}

		if (strcmp( plainfile, cipherfile ) == 0)
		{	fprintf(stderr, "\aFile '%s' cannot be both input and output file.\n", plainfile );
			goto user_error;		/*	error: same filenames for both files */
		}

		if (! file_exists( cipherfile ))
		{	fprintf(stderr, "\a\nError: Cipher or signature file '%s' does not exist.\n",
				cipherfile);
			goto user_error;
		}

		get_header_info_from_file( cipherfile, header, 4 );
		if (!is_ctb(header[0]) && is_uufile(cipherfile))
		{	
			if (verbose) fprintf(stderr,"uudecoding %s...",cipherfile);
			status = uud_file(cipherfile, SCRATCH_CTX_FILENAME);
			if (status==0)
			{	if (verbose) fprintf(stderr,"...done.\n");
				remove( cipherfile ); /* dangerous.  sure hope rename works... */
				rename( SCRATCH_CTX_FILENAME, cipherfile );
			}
			else fprintf(stderr,"\n\aError: uudecode failed for file %s\n",cipherfile);
		}

		/*---------------------------------------------------------*/
		do	/* while nested parsable info present */ 
		{
			if (get_header_info_from_file( cipherfile, &ctb, 1) < 0)
			{	fprintf(stderr,"\n\aCan't open ciphertext file '%s'\n",cipherfile);
				goto user_error;
			}

			if (!is_ctb(ctb))	/* not a real CTB -- complain */
				goto reject;

			/* PKE is Public Key Encryption */
			if (is_ctb_type( ctb, CTB_PKE_TYPE ))
			{
				fprintf(stderr,"\nFile is encrypted.  Secret key is required to read it. ");

				status = decryptfile( cipherfile, plainfile );

				if (status < 0) /* error return */
					goto user_error; 
				if (status < 1)	/* output file has no nested info? */
					break;	/* no nested parsable info.  exit loop. */

				/* Nested parsable info indicated.  Process it. */
				wipefile( SCRATCH_CTX_FILENAME );
				remove( SCRATCH_CTX_FILENAME );
				rename( plainfile,  SCRATCH_CTX_FILENAME );
				strcpy( cipherfile, SCRATCH_CTX_FILENAME );
				continue;	/* skip rest of loop */
			}	/* outer CTB is PKE type */


			if (is_ctb_type( ctb, CTB_SKE_TYPE ))
			{
				fprintf(stderr,"\nFile has signature.  Public key is required to check signature. ");

				status = check_signaturefile( cipherfile, plainfile );

				if (status < 0) /* error return */
					goto user_error;

				if (status < 1)	/* output file has no nested info? */
					break;	/* no nested parsable info.  exit loop. */

				/* Nested parsable info indicated.  Process it. */
				/* Destroy signed plaintext, if it's in a scratchfile. */
				wipefile( SCRATCH_CTX_FILENAME );
				remove( SCRATCH_CTX_FILENAME );
				rename( plainfile,  SCRATCH_CTX_FILENAME );
				strcpy( cipherfile, SCRATCH_CTX_FILENAME );
				continue;	/* skip rest of loop */
			}	/* outer CTB is SKE type */


			if (ctb == CTB_CKE)
			{	/* Conventional Key Encrypted ciphertext. */
				fprintf(stderr,"\nFile is conventionally encrypted.  Pass phrase required to read it. ");
				status = bass_decryptfile( cipherfile, plainfile );
				if (status < 0) /* error return */
					goto user_error; 
				if (status < 1)	/* output file has no nested info? */
					break;	/* no nested parsable info.  exit loop. */
				/* Nested parsable info indicated.  Process it. */
				wipefile( SCRATCH_CTX_FILENAME );
				remove( SCRATCH_CTX_FILENAME );
				rename( plainfile,  SCRATCH_CTX_FILENAME );
				strcpy( cipherfile, SCRATCH_CTX_FILENAME );
				continue;	/* skip rest of loop */
			}	/* CTB is CKE type */


			if (is_ctb_type( ctb, CTB_COMPRESSED_TYPE ))
			{	/* Compressed text. */
				status = decompress_file( cipherfile, plainfile );
				if (status < 0) /* error return */
					goto user_error;
				/* Always assume nested information... */ 
				/* Destroy compressed plaintext, if it's in a scratchfile. */
				wipefile( SCRATCH_CTX_FILENAME );
				remove( SCRATCH_CTX_FILENAME );
				rename( plainfile,  SCRATCH_CTX_FILENAME );
				strcpy( cipherfile, SCRATCH_CTX_FILENAME );
				continue;	/* skip rest of loop */
			}	/* CTB is COMPRESSED type */


			if (is_ctb_type( ctb, CTB_LITERAL_TYPE ))
			{	/* Raw plaintext.  Just copy it.  No more nesting. */
				/* Strip off CTB_LITERAL prefix byte from file: */
				status = strip_literal( cipherfile, plainfile );
				break;	/* no nested parsable info.  exit loop. */
			}	/* CTB is LITERAL type */


			if ((ctb == CTB_CERT_SECKEY)
			||  (ctb == CTB_CERT_PUBKEY))
			{	/* Key ring.  View it. */
				fprintf(stderr, "\nFile contains key(s).  Contents follow..." );

				if (view_keyring( NULL, cipherfile ) < 0)
					goto user_error;

				/*	No output file--what should we do with plainfile?
					We know that we have already prevented original 
					cipher filename from being same as plain filename.
				*/

				if (strcmp( cipherfile, SCRATCH_CTX_FILENAME ) == 0)
				{	/* key was nested in signed or enciphered file */
					remove( plainfile );
					rename( cipherfile, plainfile );
				}
				exit(0);	/* no nested parsable info. */
				/* strcpy(plainfile,"");	/* no further nesting */
				/* break;	/* no nested parsable info.  exit loop. */
			}	/* key ring.  view it. */

reject:		fprintf(stderr,"\a\nError: '%s' is not a cipher, signature, or key file.\n",
				cipherfile);
			goto user_error;

		}	while (TRUE);

		/* No more nested parsable information */

		/* Destroy any sensitive information in scratchfile: */
		wipefile( SCRATCH_CTX_FILENAME );
		remove( SCRATCH_CTX_FILENAME );

		if (!verbose)	/* if other filename messages were supressed */
			fprintf(stderr,"\nPlaintext filename: %s ", plainfile);


		/*---------------------------------------------------------*/

		/*	One last thing-- let's attempt to classify some of the more 
			frequently occurring cases of plaintext output files, as an 
			aid to the user.  

			For example, if output file is a public key, it should have
			the right extension on the filename.

			Also, it will likely be common to encrypt PKZIP files, so
			they should be renamed with the .zip extension.
		*/
		get_header_info_from_file( plainfile, header, 4 );

		if (header[0] == CTB_CERT_PUBKEY)
		{	/* Special case--may be public key, worth renaming */
			fprintf(stderr, "\nPlaintext file '%s' looks like it contains a public key.",
				plainfile );
			maybe_force_extension( plainfile, PUB_EXTENSION );
		}	/* Possible public key output file */

		else
		if (pkzipSignature( header ))
		{	/*	Special case--may be a PKZIP file, worth renaming	*/
			fprintf(stderr, "\nPlaintext file '%s' looks like a PKZIP file.",
				plainfile );
			maybe_force_extension( plainfile, ".zip" );
		}	/*	Possible PKZIP output file	*/

		else
		if ((header[0] == CTB_PKE) 
		 || (header[0] == CTB_SKE) 
	   	 || (header[0] == CTB_CKE))
		{	/* Special case--may be another ciphertext file, worth renaming */
			fprintf(stderr, "\n\aOutput file '%s' may contain more ciphertext or signature.",
				plainfile );
			maybe_force_extension( plainfile, ".ctx" );
		}	/* Possible ciphertext output file */

		exit(0);	/* no nested parsable info. */

	}	/* Decrypt file, or check signature, or show key */


user_error:	/* comes here if user made a boo-boo. */
	fprintf(stderr,"\nFor more help, consult the PGP User's Guide.");

usage:
	fprintf(stderr,"\nUsage summary:");
	fprintf(stderr,"\nTo encrypt a plaintext file with recipent's public key, type:");
	fprintf(stderr,"\n   pgp -e textfile her_userid      (produces textfile.ctx)");
	fprintf(stderr,"\nTo sign a plaintext file with your secret key, type:");
	fprintf(stderr,"\n   pgp -s textfile your_userid     (produces textfile.ctx)");
	fprintf(stderr,"\nTo sign a plaintext file with your secret key, and then encrypt it "
		   "\n   with recipent's public key, producing a .ctx file:");
	fprintf(stderr,"\n   pgp -es textfile her_userid your_userid");
	fprintf(stderr,"\nTo encrypt with conventional encryption only:  pgp -c textfile");
	fprintf(stderr,"\nTo decrypt or check a signature for a ciphertext (.ctx) file:");
	fprintf(stderr,"\n   pgp ciphertextfile [plaintextfile]");
	fprintf(stderr,"\nTo generate your own unique public/secret key pair, type:  pgp -k");
	fprintf(stderr,"\nTo add a public or secret key file's contents to your public "
		   "\n   or secret key ring:   pgp -a keyfile [keyring]");
	fprintf(stderr,"\nTo remove a key from your public key ring:     pgp -r userid [keyring]");
	fprintf(stderr,"\nTo view the contents of your public key ring:  pgp -v [userid] [keyring] ");
	exit(1);	/* error exit */

}	/* main */

