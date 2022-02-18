/*
**	lfsr.c - Linear Feedback Shift Register (LFSR) routines.
**	(c) 1988 Philip Zimmermann.  All rights reserved.
**	10 Sep 88 -- revised 20 Jun 89
*/

#include "lfsr.h"	/* Linear Feedback Shift Register headers */

/* Calling routines must declare lfsr buffer and byte index into it.: */
/* byte lfsr[256] = {0}; */
/* byte rtail = 0;	/* points to 256, which is same as 0 */


/*
**	steplfsr256 - Step big linear feedback shift register (LFSR)
**	256 cycles.  Use primitive polynomial:  X^255 + X^82 + X^0
**	Actually runs 8 LFSR's in parallel, outputting a whole byte
**	with each step.
*/
void steplfsr256(register byteptr lfsr)
{	register byte ltail;
	register byte ltap0;
	register byte ltap82;
	register byte ltap255;
	ltail = 0; ltap0 = 0; ltap82 = 82; ltap255 = 255;
	do
		lfsr[--ltail] = lfsr[ltap0--]^lfsr[ltap82--]^lfsr[ltap255--];
	while (ltail);
} /* steplfsr256 */


/*
**	getlfsr - get 1 byte from lfsr buffer.
**	Calls steplfsr256() if necessary to replenish lfsr buffer.
**
**	getlfsr() is a #define in the header file "lfsr.h"
*/


/*
**	initlfsr - initialize linear feedback shift register
**
**	Since each of the 8 bits of the bytes in the LFSR array represents
**	a separate independant LFSR, we must be sure the every one of the
**	8 LFSRs have some 1's and 0's in it.  Therefore, an unmodified
**	7-bit ASCII string is not an acceptable seed for the LFSR byte
**	array, because the high bits are all zeros.  That's why we do a
**	cumulative add on the seed bits, to mix the seed bits up between
**	the 8 LFSRs.
*/
void initlfsr(byteptr seed, short size, byteptr lfsr, byte *rtail)
/*	seed is random number seed.
	size is number of bytes in seed.
	lfsr is pointer to 256-byte LFSR buffer.
	*rtail is rtail index byte.
*/
{	short i;
	unsigned int c;
#ifdef CHECKLFSR
	byte check1,check0;	/* to ensure 1s and 0s mixed in each LFSR */
	check0 = 0x00;		/* should end up as 0xff after ORing */
	check1 = 0xff;		/* should end up as 0x00 after ANDing */
#endif	/* CHECKLFSR */
	*rtail = 0;		/* points to 256, which is same as 0 */
	c = size;		/* makes seed "AAA" distinct from seed "AAAAAA" */
	for (i=0; i<=255; i++)	/* make several seed copies across the LFSR */
	{	c += seed[i % size];	/* cumulatively add the seed data */
		lfsr[i] = c + (c>>8);	/* wraparound carry bits */
#ifdef CHECKLFSR
		check0 |= lfsr[i];	/* scan for all zeros in any LFSR row */
		check1 &= lfsr[i];	/* scan for all ones in any LFSR row */
#endif	/* CHECKLFSR */
	}
#ifdef CHECKLFSR
	/* if any LFSR row contained all zeros, check0 will not be 0xff */
	/* if any LFSR row contained all ones, check1 will not be 0x00 */
	c = 0xFF & (check1 | ~check0);	/* should be 0x00 if all went OK. */
	/* Now guarantee that all 8 LFSRs contain a mix of 1s and 0s... */
	if (c) printf("\nLFSR check0=%2X check1=%2X. ",check0,check1);
	lfsr[0] ^= c;		/* flip some faulty bits if we have to */
#endif	/* CHECKLFSR */
} /* initlfsr */


/*
**	stomplfsr - inverts about half the bits in an LFSR.
**
**	If the LFSR has a "rail" of almost all 0's or almost all 1's in
**	the same bit position, it will perform poorly as a random number
**	generator.  This function will probably fix this condition.
*/
void stomplfsr(byteptr lfsr)
/*	lfsr is pointer to 256-byte LFSR buffer. */
{	byte i;
	i=255;
	while (i) *lfsr++ ^= i--;
} /* stomplfsr */


