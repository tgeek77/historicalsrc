/*	basslib.h - include file for BassOmatic encipherment functions.

	(c) Copyright 1988 by Philip Zimmermann.  All rights reserved.  
	This software may not be copied without the written permission of 
	Philip Zimmermann.  The author assumes no liability for damages
	resulting from the use of this software, even if the damage results
	from defects in this software.  No warranty is expressed or implied.
*/

/* Elaborate protection mechanisms to assure no redefinitions of types...*/
#ifndef BOOLSTUFF
#define BOOLSTUFF
#ifndef TRUE
#define FALSE 0
#define TRUE (!FALSE)
#endif	/* if TRUE not already defined */
typedef unsigned char boolean;	/* values are TRUE or FALSE */
#endif	/* if BOOLSTUFF not already defined */
#ifndef BYTESTUFF
#define BYTESTUFF
typedef unsigned char byte;	/* values are 0-255 */
typedef byte *byteptr;	/* pointer to byte */
typedef char *string;	/* pointer to ASCII character string */
#endif	/* if BYTESTUFF not already defined */
#ifndef WORDSTUFF
#define WORDSTUFF
typedef unsigned short word16;	/* values are 0-65536 */
typedef unsigned long word32;	/* values are 0-4294967296 */
#endif	/* if WORDSTUFF not already defined */
#ifndef min	/* if min macro not already defined */
#define min(a,b) ( (a)<(b) ? (a) : (b) )
#define max(a,b) ( (a)>(b) ? (a) : (b) )
#endif	/* if min macro not already defined */


#define MAXKEYLEN 254	/* max byte length of BassOmatic key */

#define NTABLES 8		/* number of random permutation vectors */

typedef struct {
	boolean	initialized;	/* determines whether key context is defined */
	byteptr	tlist[NTABLES];	/* list of permutation table pointers */
	byte	bitmasks[NTABLES]; /* bitshredder bitmasks with 50% bits set */
	byteptr	iv; /* CFB Initialization Vector used by initcfb and basscfb */
	boolean cfbuncryp;	/* TRUE means decrypting (in CFB mode) */
	boolean uncryp;		/* TRUE means decrypting (in ECB mode) */
/* The following parameters are computed from the key control byte...*/
	char	nrounds;	/* specifies number of rounds thru BassOmatic */
	boolean hardrand;	/* means regenerate tables with BassOmatic */
	boolean shred8ways;	/* means use 8-way bit shredding */
	boolean rerand;		/* means replenish tables with every block */
	byteptr	lfsr;		/* Linear Feedback Shift Register */
	byte	rtail;		/* rtail is an index into LFSR buffer */
	} KEYCONTEXT;


/*
**	initbassrand - initialize bassrand, BassOmatic random number generator.
**		Must close via closebass().
*/
void initbassrand(byteptr key, short keylen, byteptr seed, short seedlen);


/*
**	bassrand - BassOmatic pseudo-random number generator.
*/
byte bassrand(void);


/*
**	bass_save - saves BassOmatic key context in context structure.
*/
void bass_save(KEYCONTEXT *context);


/*
**	bass_restore - restore BassOmatic key context from context structure.
*/
void bass_restore(KEYCONTEXT *context);


/*
**	closebass - end the current BassOmatic key context, freeing its buffers.
*/
void closebass(void);

int initkey(byteptr key, short keylen, boolean decryp);
	/* Sets up key schedule for BassOmatic. */

void bassomatic(byteptr in, byteptr out);
	/* Encipher 1 block with the BassOmatic ECB mode. */

/*
**	initcfb - Initializes the BassOmatic key schedule tables via key,
**	and initializes the Cipher Feedback mode IV.
*/
int initcfb(byteptr iv0, byteptr key, short keylen, boolean decryp);


/*
**	basscfb - encipher 1 block with BassOmatic enciphering algorithm,
**		using Cipher Feedback (CFB) mode.
**
**	Assumes initcfb has already been called.  References global iv byteptr.
*/
void basscfb(byteptr buf, int count);


/*
**	fillbuf(dst,count,c) - fill byte buffer dst with byte c
*/
void fillbuf(register byteptr dst, register short count, register byte c);


/*
**	crc() - compute CRC-16 of buffer
*/
word16 crc(register byteptr buf, int count);


