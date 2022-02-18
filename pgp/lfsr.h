/*	lfsr.h - C header include file for lfsr.c
**	Linear Feedback Shift Register (LFSR) routines
**	(c) 1988 Philip Zimmermann.  All rights reserved.
*/


/* Elaborate protection mechanisms to assure no redefinitions of types...*/
#ifndef BYTESTUFF
#define BYTESTUFF
typedef unsigned char byte;	/* values are 0-255 */
typedef byte *byteptr;	/* pointer to byte */
typedef char *string;	/* pointer to ASCII character string */
#endif	/* if BYTESTUFF not already defined */


/*
**	steplfsr256 - Step big linear feedback shift register (LFSR)
**	256 cycles.  Use primitive polynomial:  X^255 + X^82 + X^0
**	Actually runs 8 LFSR's in parallel, outputting a whole byte
**	with each step.
*/
void steplfsr256(register byteptr lfsr);

/*
**	getlfsr - get 1 byte from lfsr buffer.  Must be macro, not function.
**	Calls steplfsr256() if necessary to replenish lfsr buffer.
*/
#define getlfsr(lfsr,rtail) (rtail ? lfsr[--rtail] : \
				(steplfsr256(lfsr),lfsr[--rtail]))


/*
**	initlfsr - initialize linear feedback shift register
*/
void initlfsr(byteptr seed, short size, byteptr lfsr, byte *rtail);

/*
**	stomplfsr - inverts about half the bits in an LFSR.
**
**	If the LFSR has a "rail" of almost all 0's or almost all 1's in
**	the same bit position, it will perform poorly as a random number
**	generator.  This function will probably fix this condition.
*/
void stomplfsr(byteptr lfsr);


