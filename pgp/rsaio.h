/*	C include file for RSA library I/O routines

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

	NOTE:  This assumes previous inclusion of "rsalib.h"
*/

/* #define XHIGHFIRST */ /* determines external integer byteorder for I/O */

/*--------------------- Byte ordering stuff -------------------*/
#ifdef NEEDSWAP
#undef NEEDSWAP	/* make sure NEEDSWAP is initially undefined */
#endif

#ifdef HIGHFIRST	/* internal HIGHFIRST byte order */
#ifndef XHIGHFIRST	/* external LOWFIRST byte order */
#define NEEDSWAP /* internal byteorder differs from external byteorder */
#endif
#else	/* internal LOWFIRST byte order */
#ifdef XHIGHFIRST	/* external HIGHFIRST byte order */
#define NEEDSWAP /* internal byteorder differs from external byteorder */
#endif
#endif	/* internal LOWFIRST byte order */

#ifdef NEEDSWAP
#define hilo_swap(r1,numbytes) hiloswap(r1,numbytes)
#define convert_order(r) hiloswap(r,units2bytes(global_precision))
#else
/* hilo_swap is nil because external representation is already the same */
#define hilo_swap(r1,numbytes)	/* nil statement */
#define convert_order(r)	/* nil statement */
#endif	/* not NEEDSWAP */

/*------------------ End byte ordering stuff -------------------*/


#ifndef RSAIO	/* not compiling RSAIO */
	/*	Bug in DSP2101 C compiler -- no function protypes 
		allowed when compiling those same functions. */

#ifdef EMBEDDED
int putchar(int c);		/* standard C library function from <stdio.h> */
#endif	/* EMBEDDED */

int string_length(char *s);
	/* Returns string length */

int str2reg(unitptr reg,string digitstr);
	/* Converts a possibly-signed digit string into a large binary number.
	   Returns assumed radix, derived from suffix 'h','o',b','.' */

void putstr(string s); /* Put out null-terminated ASCII string via putchar. */
void puthexbyte(byte b); /* Put out byte in ASCII hex via putchar. */
void puthexw16(word16 w); /* Put out 16-bit word in hex, high byte first. */

int display_in_base(string s,unitptr n,short radix);
	/* Display n in any base, such as base 10.  Returns number of digits. */

void mp_display(string s,unitptr r);
	/* Display register r in hex, with prefix string s. */

word16 checksum(register byteptr buf, register word16 count);
	/* Returns checksum of buffer. */

void fill0(byteptr buf,word16 bytecount);
	/* Zero-fill the byte buffer. */

void cbc_xor(register unitptr dst, register unitptr src, word16 bytecount);
	/* Performs the XOR necessary for RSA Cipher Block Chaining. */

void hiloswap(byteptr r1,short numbytes);
	/* Reverses the order of bytes in an array of bytes. */

short mpi2reg(register unitptr r, register byteptr buf);
	/* Converts to unit array from byte array with bit length prefix word. */

short reg2mpi(register byteptr buf, register unitptr r);
	/* Converts from unit array to byte array with bit length prefix word. */

short preblock(unitptr outreg, byteptr inbuf, short bytecount,
	unitptr modulus, boolean cksbit, byteptr randompad);
	/* Converts plaintext block into form suitable for RSA encryption. */

short postunblock(byteptr outbuf, unitptr inreg,
	unitptr modulus, boolean padded, boolean cksbit);
	/*	Converts a just-decrypted RSA block back 
		into unblocked plaintext form. */

#endif	/* not compiling RSAIO */

/****************** end of RSA I/O library ************************/

