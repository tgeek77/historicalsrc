/*	C source code for RSA library I/O routines.
	Implemented Nov 86 by Philip Zimmermann
	Last revised 11 Apr 91 by PRZ

	Boulder Software Engineering
	3021 Eleventh Street
	Boulder, CO 80304
	(303) 444-4541

	(c) Copyright 1986 by Philip Zimmermann.  All rights reserved.
	The author assumes no liability for damages resulting from the use 
	of this software, even if the damage results from defects in this 
	software.  No warranty is expressed or implied.  

	The external data representation for RSA messages and keys that
	some of these library routines assume is outlined in a paper by 
	Philip Zimmermann, "A Proposed Standard Format for RSA Cryptosystems",
	IEEE Computer, September 1986, Vol. 19 No. 9, pages 21-34.
	Some revisions to this data format have occurred since the paper
	was published.
*/

/* #define DEBUG */


#ifndef EMBEDDED	/* not EMBEDDED - not compiling for embedded target */
#include <stdio.h> 	/* for printf, etc. */
#else	/* EMBEDDED - compiling for embedded target */
#define NULL (void *)0
#endif

#include "rsalib.h"
#define RSAIO
#include "rsaio.h"


/*----------------- Following procedures relate to I/O ------------------*/

int string_length(char *s)
	/* Returns string length, just like strlen() from <string.h> */
{	int i;
	i = 0;
	while (*s++) i++;
	return (i);	
}	/* string_length */


static int ctox(int c)
	/* Returns integer 0-15 if c is an ASCII hex digit, -1 otherwise. */
{	if ((c >= '0') && (c <= '9'))
		return(c - '0');
	if ((c >= 'a') && (c <= 'f'))
		return((c - 'a') + 10);
	if ((c >= 'A') && (c <= 'F'))
		return((c - 'A') + 10);
	return(-1);		/* error -- not a hex digit */
}	/* ctox */


int str2reg(unitptr reg,string digitstr)
	/* Converts a possibly-signed digit string into a large binary number.
	   Returns assumed radix, derived from suffix 'h','o',b','.' */
{	unit temp[MAX_UNIT_PRECISION],base[MAX_UNIT_PRECISION];
	int c,i;
	boolean minus = FALSE;
	short radix;	/* base 2-16 */

	mp_init(reg,0);
	
	i = string_length(digitstr);
	if (i==0) return(10);		/* empty string, assume radix 10 */
	c = digitstr[i-1];		/* get last char in string */
	
	switch (c)	/* classify radix select suffix character */
	{
	case '.':	radix = 10;
			break;
	case 'H':
	case 'h':	radix = 16;
			break;
	case 'O': 
	case 'o':	radix = 8;
			break;
	case 'B':
	case 'b':	radix = 2;	/* caution! 'b' is a hex digit! */
			break;
	default:	radix = 10;
	}

	mp_init(base,radix);
	if (minus = (*digitstr == '-')) digitstr++;
	while (c = *digitstr++)
	{	if (c==',') continue;	/* allow commas in number */
		c = ctox(c);
		if ((c < 0) || (c >= radix)) 
			break;	/* scan terminated by any non-digit */
		mp_mult(temp,reg,base);
		mp_move(reg,temp);
		mp_init(temp,c);
		mp_add(reg,temp);
	}
	if (minus) mp_neg(reg);
	return(radix);
} /* str2reg */


/*	These I/O functions, such as putstr, puthexbyte, and puthexw16, 
	are provided here to avoid the need to link in printf from the 
	C I/O library.  This is handy in an embedded application.
*/

#ifdef EMBEDDED		/* if compiling for embedded target */
int putchar(int c)	/* standard C library function */
{	/* stub -- replace with putchar suitable for embedded target. */
}	/* putchar */
#endif	/* if compiling for embedded target */

void putstr(string s)
	/* Put out null-terminated ASCII string via putchar. */
{	while (*s) putchar(*s++);
}	/* putstr */

void puthexbyte(byte b)
	/* Put out byte in ASCII hex via putchar. */
{	static const char *nibs = "0123456789ABCDEF";
	putchar(nibs[b >> 4]);
	putchar(nibs[b & 0x0F]);
}	/* puthexbyte */

void puthexw16(word16 w)
	/* Put out 16-bit word in hex, high byte first. */
{	puthexbyte((byte)(w >> 8));
	puthexbyte((byte)(w & 0xFF));
}	/* puthexw16 */

#ifdef UNIT32
static void puthexw32(word32 lw)
	/* Puts out 32-bit word in hex, high byte first. */
{	puthexw16((word16)(lw>>16));
	puthexw16((word16)(lw & 0xFFFFL));
}	/* puthexw32 */
#endif	/* UNIT32 */


#ifdef UNIT8
#define puthexunit(u) puthexbyte(u)
#endif
#ifdef UNIT16
#define puthexunit(u) puthexw16(u)
#endif
#ifdef UNIT32
#define puthexunit(u) puthexw32(u)
#endif


void fill0(byteptr buf,word16 bytecount)
	/* Zero-fill the byte buffer. */
{	while (bytecount--) *buf++ = 0;
}	/* fill0 */


int display_in_base(string s,unitptr n,short radix)
	/* Display n in any base, such as base 10.  Returns number of digits. */
	/*	s is string to label the displayed register.
		n is multiprecision integer.
		radix is base, 2-16. 
	*/
{
	char buf[MAX_BIT_PRECISION + (MAX_BIT_PRECISION/8) + 2];
	unit r[MAX_UNIT_PRECISION],quotient[MAX_UNIT_PRECISION];
	word16 remainder;
	char *bp = buf;
	char minus = FALSE;
	int places = 0;
	int commaplaces;	/* put commas this many digits apart */
	int i;

	/*	If string s is just an ESC char, don't print it.
		It's just to inhibit the \n at the end of the number.
	*/
	if ((s[0] != '\033') || (s[1] != '\0'))
		putstr(s);

	if ( (radix < 2) || (radix > 16) )
	{	putstr("****\n");	/* radix out of range -- show error */
		return(-1);
	}
	commaplaces = (radix==10 ? 3 : (radix==16 ? 4 :
			(radix==2 ? 8 : (radix==8 ? 8 : 1))));
	mp_move(r,n);
	if ((radix == 10) && mp_tstminus(r))
	{	minus = TRUE;
		mp_neg(r);	/* make r positive */
	}

	*bp = '\0';
	do	/* build backwards number string */
	{	if (++places>1)
			if ((places % commaplaces)==1)
				*++bp = ',';	/* 000,000,000,000 */
		remainder = mp_shortdiv(quotient,r,radix);
		*++bp = "0123456789ABCDEF" [remainder]; /* Isn't C wonderful? */
		mp_move(r,quotient);
	} while (testne(r,0));
	if (minus)
		*++bp = '-';
	
	if (commaplaces!=1)
		while ((++places % commaplaces) != 1)
			*++bp = ' '; /* pad to line up commas */

	i = string_length(s);
	while (*bp)
	{	putchar(*bp);
		++i;
		if ((*bp == ',') || commaplaces==1)
			if (i > (72-commaplaces))
			{	putchar('\n'); 
				i=string_length(s); 
				while (i--) putchar(' ');
				i = string_length(s);
			}
		bp--;
	}
	switch (radix)
	{	/* show suffix character to designate radix */
	case 10: /* decimal */
		putchar('.');
		break;
	case 16: /* hex */
		putchar('h');
		break;
	case 8: /* octal */
		putchar('o');
		break;
	case 2: /* binary */
		putchar('b');
		break;
	default: /* nonstandard radix */
		/* printf("(%d)",radix); */ ;	
	}

	if ((s[0] == '\033') && (s[1] == '\0'))
		putchar(' ');	/* supress newline */
	else putchar('\n');

	fill0(buf,sizeof(buf));	/* burn the evidence on the stack...*/
	/* Note that local stack arrays r and quotient are now 0 */
	return(places);
}	/* display_in_base */


void mp_display(string s,unitptr r)
	/* Display register r in hex, with prefix string s. */
{	short precision;
	int i,j;
	putstr(s);
	normalize(r,precision);	/* strip off leading zeros */
	if (precision == 0)
	{	putstr(" 0\n");
		return;
	}
	make_msbptr(r,precision);
	i=0;
	while (precision--)
	{	if (!(i++ % (16/BYTES_PER_UNIT)))
		{	if (i>1)
			{	putchar('\n'); 
				j=string_length(s); 
				while (j--) putchar(' ');
			}
		}
		puthexunit(*r);
		putchar(' ');
		post_lowerunit(r);
	}
	putchar('\n');
}	/* mp_display */


word16 checksum(register byteptr buf, register word16 count)
	/* Returns checksum of buffer. */
{	word16 cs;
	cs = 0;
	while (count--) cs += *buf++;
	return(cs);
} /* checksum */


void cbc_xor(register unitptr dst, register unitptr src, word16 bytecount)
	/*	Performs the XOR necessary for RSA Cipher Block Chaining.
		The dst buffer ought to have 1 less byte of significance than 
		the src buffer.  Only the least significant part of the src 
		buffer is used.  bytecount is the size of a plaintext block.
	*/
{	short nunits;	/* units of precision */
	nunits = bytes2units(bytecount)-1;
	make_lsbptr(dst,global_precision);
	while (nunits--)
	{	*dst ^= *post_higherunit(src);
		post_higherunit(dst);
		bytecount -= units2bytes(1);
	}
	/* on the last unit, don't xor the excess top byte... */
	*dst ^= (*src & (power_of_2(bytecount<<3)-1));
}	/* cbc_xor */


void hiloswap(byteptr r1,short numbytes)
	/* Reverses the order of bytes in an array of bytes. */
{	byteptr r2;
	byte b;
	r2 = &(r1[numbytes-1]);
	while (r1 < r2)	
	{	b = *r1; *r1++ = *r2; *r2-- = b;
	}
}	/* hiloswap */


#define byteglue(lo,hi) ((((word16) hi) << 8) + (word16) lo)


short mpi2reg(register unitptr r,register byteptr buf)
/*	Converts a multiprecision integer from the externally-represented 
	form of a byte array with a 16-bit bitcount in a leading length 
	word to the internally-used representation as a unit array.
	Converts to INTERNAL byte order.
	The same buffer address may be used for both r and buf.
	Returns number of units in result, or returns -1 on error.
*/
{	byte buf2[MAX_BYTE_PRECISION];
	word16 bytecount, unitcount, zero_bytes, i;
	word16 lowcount,highcount;

	/* First, extract 16-bit bitcount prefix from first 2 bytes... */
#ifdef XHIGHFIRST
	highcount = *buf++;
	lowcount = *buf++;
#else
	lowcount = *buf++;
	highcount = *buf++;
#endif
	/* Convert bitcount to bytecount and unitcount... */	
	bytecount = bits2bytes(byteglue(lowcount,highcount));
	unitcount = bytes2units(bytecount);
	if (unitcount > global_precision)
	{	/* precision overflow during conversion. */
		return(-1);	/* precision overflow -- error return */
	}
	zero_bytes = units2bytes(global_precision) - bytecount;

#ifdef XHIGHFIRST
	fill0(buf2,zero_bytes);  /* fill leading zero bytes */
	i = zero_bytes;
#else
	fill0(buf2+bytecount,zero_bytes);  /* fill trailing zero bytes */
	i = 0;
#endif
	while (bytecount--) buf2[i++] = *buf++;

	convert_order(buf2);	/* convert to INTERNAL byte order */
	mp_move(r,(unitptr)buf2);
	mp_burn((unitptr)buf2);	/* burn the evidence on the stack */
	return(unitcount);	/* returns unitcount of reg */
}	/* mpi2reg */


short reg2mpi(register byteptr buf,register unitptr r)
/*	Converts the multiprecision integer r from the internal form of 
	a unit array to the normalized externally-represented form of a 
	byte array with a leading 16-bit bitcount word in buf[0] and buf[1].
	This bitcount length prefix is exact count, not rounded up.
	Converts to EXTERNAL byte order.
	The same buffer address may be used for both r and buf.
	Returns the number of bytes of the result, not counting length prefix.
*/
{	byte buf1[MAX_BYTE_PRECISION];
	byteptr buf2;
	short bytecount,bc;
	word16 bitcount;
	bitcount = countbits(r);
	bytecount = bits2bytes(bitcount);
	bc = bytecount;	/* save bytecount for return */
	buf2 = buf1;
	mp_move((unitptr)buf2,r);
	convert_order(buf2);	/* convert to EXTERNAL byte order */
#ifdef XHIGHFIRST	
	/* Skip over leading zero bytes. */
	buf2 += (units2bytes(global_precision) - bytecount);
	*buf++ = bitcount >> 8;		/* store bitcount with high byte first */
	*buf++ = bitcount & 0xff;
#else
	*buf++ = bitcount & 0xff;	/* store bitcount with low byte first */
	*buf++ = bitcount >> 8;
#endif	/* not XHIGHFIRST */

	while (bytecount--) *buf++ = *buf2++;

	mp_burn((unitptr)buf1);	/* burn the evidence on the stack */
	return(bc);		/* returns bytecount of mpi, not counting prefix */
}	/* reg2mpi */


#ifdef DEBUG

void dumpbuf(string s, byteptr buf, int bytecount)
	/* Dump buffer in hex, with string label prefix. */
{	putstr(s);
	while (bytecount--)
	{	puthexbyte(*buf++);
		putchar(' ');
		if ((bytecount & 0x0f)==0)
			putchar('\n');
	}
} /* dumpbuf */

void dump_unit_array(string s, unitptr r)
/*	Dump unit array r as a C array initializer, with string label prefix. 
	Array is dumped in native unit order.
*/
{	int unitcount;
	unitcount = significance(r);
	putstr(s);
	putstr("\n{ ");
	while (unitcount--)
	{	putstr("0x");
		puthexunit(*r++);
		putchar(',');
		if (unitcount && ((unitcount & 0x07)==0))
			putstr("\n  ");
	}
	putstr(" 0};\n");
} /* dump_unit_array */

#endif	/* ifdef DEBUG */


/*
**	short preblock(outreg, inbuf, bytecount, modulus, cksbit, randompad)
**
**	A plaintext message must be converted into an integer less than
**	the modulus n.  We do this by making it 1 byte shorter than the
**	normalized modulus n.  Short blocks are left justified and padded.
**	The last pad byte is a count of how many pad bytes were required,
**	including itself.  Then the 16-bit checksum is appended.
**
**	When using very long keys, if there are more than 255 bytes 
**	of padding, the extra pad bytes will all be 0.  The first 
**	nonzero pad byte from the end will contain the count of the 
**	pad bytes preceding it, which should be 255 if there were more 
**	than 255 total pad bytes.
**
**	For example, suppose the 5-byte string "hello" were the plaintext
**	that needed preblocking, and the modulus was 11 bytes long, and
**	nonrandom padding with a 16-bit checksum was applied.  Here it is 
**	after preblocking, assuming an LSB-first external format:
**	(LSB)                              (MSB)
**	'h','e','l','l','o',1,2,3,low_checksum,high_checksum,0,<slop zeros>
**
**	But if XHIGHFIRST were defined, it would be blocked this way:
**	         (MSB)                              (LSB)
**	<slop zeros>,0,'h','e','l','l','o',1,2,3,high_checksum,low_checksum
*/
short preblock(unitptr outreg, byteptr inbuf, short bytecount,
	unitptr modulus, boolean cksbit, byteptr randompad)
/*	Converts plaintext block into form suitable for RSA encryption.
	Converts to INTERNAL byte order.
	Returns # of bytes remaining to process.  Note that the same buffer 
	address may be used for both outreg and inbuf.
	cksbit is TRUE iff checksum word should be appended to block.
	randompad is a pointer to a buffer of random pad bytes to use for 
	padding material, or NULL iff we want to use constant padding.
*/
{	byte out[MAX_BYTE_PRECISION];
	byte pad;
	short i,byte_precision,leading_zeros,remaining,blocksize,padsize;
	short excess_pads;	/* number of trailing zeros in long pads */
	short startbyte;
	word16 chksum;

	byte_precision = units2bytes(global_precision);
	leading_zeros = byte_precision - countbytes(modulus) + 1;
	blocksize = byte_precision - leading_zeros - (2*cksbit);
	/* note that blocksize includes data plus pad bytes, if any */

	remaining = bytecount - blocksize;
	if (remaining>=0) 
		bytecount = blocksize;
	padsize = blocksize - bytecount;	/* bytes of padding */
	pad = 0;
	i = 0;

#ifdef XHIGHFIRST
	while (leading_zeros--)	
		out[i++] = 0;
#endif
	startbyte = i;
	while (bytecount--)		/* copy user data */
		out[i++] = *inbuf++;

	/* Handle pad lengths in excess of 255 bytes... */
	excess_pads = 0;
	if (padsize > 255) 
		excess_pads = padsize - 255;	/* compute spillage */
	padsize -= excess_pads;	/* do not allow padsize > 255 */

	/* Perform either random padding or constant padding... */
	if (randompad != NULL)	/* random pad buffer provided? */ 
	{	while (padsize-- > 1)
		{	++pad;
			out[i++] = *randompad++; /* use random pad bytes */
		}
		padsize++;	/* correct last padsize-- */
	}	/* end of random padding */

	while ( padsize-- > 0 )	
		out[i++] = ++pad;

	while (excess_pads--)	/* only if more than 255 pad bytes */
		out[i++] = 0;		/* excess padding is zeros */

	/* End of padding logic */

	if (cksbit) 
	{	chksum = checksum(out+startbyte,blocksize);
#ifdef XHIGHFIRST	
		out[i++] = chksum >> 8; /* store checksum with high byte first */
		out[i++] = chksum & 0xff;
#else
		out[i++] = chksum & 0xff; /* store checksum with low byte first */
		out[i++] = chksum >> 8;
#endif	/* not XHIGHFIRST */
	}

#ifndef XHIGHFIRST
	while (leading_zeros--)	
		out[i++] = 0;
#endif
	mp_move(outreg,(unitptr)out);
	mp_burn((unitptr)out); /* burn the evidence on the stack */
	convert_order(outreg);	/* convert outreg to INTERNAL byte order */
	return(remaining);	/* less than 0 if there was padding */
}	/* preblock */


short postunblock(byteptr outbuf, unitptr inreg,
	unitptr modulus, boolean padded, boolean cksbit)
/*	Converts a just-decrypted RSA block back into unblocked plaintext form.
	Converts to EXTERNAL byte order.
	See the notes on preblocking in the preblock routine above.
	Note that outbuf must be at least as large as inreg.
	The same buffer address may be used for both outbuf and inreg.
	padded is TRUE iff block is expected to contain pad bytes.
	cksbit is TRUE iff block is expected to contain checksum word.
	Returns positive bytecount of plaintext, or negative error status.
*/
{	short i,byte_precision,leading_zeros,bytecount,blocksize;
	word16 chksum,chksumlo,chksumhi;
	word16 padsize;

	byte_precision = units2bytes(global_precision);
	leading_zeros = byte_precision - countbytes(modulus) + 1;
	blocksize = byte_precision - leading_zeros - (2*cksbit);
	/* note that blocksize includes data plus pad bytes, if any */

	mp_move((unitptr)outbuf,inreg);
	convert_order(outbuf);	/* convert to EXTERNAL byte order */

#ifndef XHIGHFIRST
#define	STARTBYTE 0
#else
#define STARTBYTE leading_zeros
#endif
	if (cksbit)
	{
#ifdef XHIGHFIRST
		chksumhi = outbuf[STARTBYTE+blocksize];
		chksumlo = outbuf[STARTBYTE+blocksize+1];
#else
		chksumlo = outbuf[STARTBYTE+blocksize];
		chksumhi = outbuf[STARTBYTE+blocksize+1];
#endif
		chksum = byteglue(chksumlo,chksumhi);

		if ( chksum != checksum(outbuf+STARTBYTE,blocksize) )
			return(-1);	/* return checksum error */
	}	/* checkum expected */

	padsize = 0;
	if (padded)
	{	i = STARTBYTE+blocksize-1;
		while (outbuf[i] == 0)	/* clip off null excess pad bytes */
		{	padsize++; i--;
		}
		padsize += outbuf[i];
	}

	if (padsize > blocksize)
	{	/* Error - pad count out of range. */
		padsize = 0; /* bogus padding means no padding */
		return(-2);	/* pad count out of range -- error return */
	}
	bytecount = blocksize - padsize;

#ifdef XHIGHFIRST
	i = 0;
	while (i++ < bytecount)
		outbuf[i-1] = outbuf[STARTBYTE+i-1];
#endif
	i = bytecount;
	while (i < byte_precision) 
		outbuf[i++] = 0;
	return(bytecount);	/* normal return */
#undef STARTBYTE
}	/* postunblock */

/****************** end of RSA I/O library ************************/

