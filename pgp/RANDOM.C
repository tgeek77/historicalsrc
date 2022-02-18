/**********************************************************************
	random.c - C source code for random number generation - 19 Nov 86
	(c) Copyright 1986 by Philip Zimmermann.  All rights reserved.  
	Revised Jul 88 by PRZ and again Dec 88 by Allan Hoeltje
		to use IBM PC 8253 timer0 for a faster counter.
	Revised Apr 89 by PRZ to recycle random bytes.
	Last revised 15 Dec 90 by PRZ.

	This code generates truly random numbers derived from a counter that is 
	incremented continuously while the keyboard is scanned for user input.
	Every time the user touches a key, the least significant bits of the 
	counter are pushed on a stack.  Later, this supply of random bytes can
	be popped off the stack by applications requiring stochastic numbers.
	Cryptographic applications require this kind of randomness.

	The only requirement to make this work is that keypress must be called 
	frequently, and/or getkey must be called to read the keyboard.  

	Note that you can only get as many random bytes as the number of 
	bytes accumulated by the user touching the keyboard.
**********************************************************************/

#include	<stdio.h>	/* for putchar() and printf() */
#include	<conio.h>	/* for kbhit() and getch() */
#include	"random.h"

/* #define USEPCTIMER  /* use fast hardware timer on IBM PC or AT or clone */
/* #define DEBUG */

#ifdef DEBUG
#define DEBUGprintf1(x) fprintf(stderr,x)
#define DEBUGprintf2(x,y) fprintf(stderr,x,y)
#else
#define DEBUGprintf1(x)
#define DEBUGprintf2(x,y)
#endif


static int randseed=0; /* used only by pseudorand() function. */
int pseudorand(void)
/*	Home-grown 16-bit LCG pseudorandom generator. */
{	randseed = (randseed*31421 + 6927) & 0xffff;
	return (randseed);
}	/* pseudorand */


int randcount = 0 ;		/* # of random bytes accumulated in pool */
static byte randpool[256] = {0} ;	/* pool of truly random bytes */
static int recyclecount = 0 ;	/* # of recycled random bytes accumulated */
static byte recyclepool[256] = {0} ; /* pool of recycled random bytes */
static int recycleptr = 0;	/* points to next byte to grab in recyclepool */

/* fastcounter is a free-running counter incremented in main event loop */
static byte fastcounter = 0;	/* not needed if we can use the PC timer. */


#ifdef USEPCTIMER	/* we will use fast hardware timer on IBM PC */
/* #include <conio.h>	/* function definitions for inp() and outp() */
/* outp() and inp() works only for Microsoft C for IBM PC or AT */
/* timer0 on 8253-5 on IBM PC or AT tics every .84 usec. */
#define timer0		0x40	/* 8253 timer 0 port */
#define timercntl	0x43	/* 8253 control register */
#define timer0rwl	0x00	/* read lo/hi bytes of cntr 2 with latch */
#define timer0rnl	0x30	/* read lo/hi bytes of cntr 2 w/o latch */

static byte latched_hitimer = 0; /* captured by keyboard ISR */
static byte latched_lotimer = 0; /* captured by keyboard ISR */
/* when kbisr captures timer, timer_latched is set. */
static boolean timer_latched = FALSE;

static void kbisr(void)	/* Keyboard Interrupt Service Routine (ISR) */
/*
	kbisr should be called on the way into, or on the way out of,
	or from within the DOS keyboard ISR, as long as it gets called
	at the time of a keyboard interrupt.  Assumes that the real
	DOS keyboard ISR captures the keystroke in the normal way.
	Only the hardware timer counter is captured by the kbisr routine,
	leaving the actual keystroke capture to the normal DOS keyboard ISR.
	We indicate that a timer capture has taken place by setting 
	timer_latched.

	NOTE: WE STILL NEED TO FIND A WAY to connect this subroutine with the 
	normal keyboard ISR, so that kbisr gets called when there's a keyboard 
	interrupt.
*/
{	outp(timercntl,timer0rwl);
	latched_lotimer = inp(timer0);
	latched_hitimer = inp(timer0);
	timer_latched = TRUE;
}	/* kbisr */

static unsigned short pctimer0(void)
{
/*	Reads and returns the hardware 8253 timer0 on the PC or AT
**	or clone, shifted right 1 bit.
**
**	DO NOT SET THE HARDWARE COUNTER TO ZERO. It is already initialized
**	by the system to be used by the clock.  It is set up in mode 3
**	(square wave rate generator) and counts down by 2 from 0 (0xFFFF+1)
**	to produce an 18.2 Hz square wave.  We may, however, READ the
**	lo and hi bytes without causing any problems.  BUT just
**	remember that the lo byte will always be even (since it is
**	counting by two).
**
**	Note that we can not use counter 1 since it is tied to the
**	dynamic RAM refresh hardware.  Counter 2 is tied to the 8255
**	PPI chip to do things like sound.  Though it would be safe to
**	use counter 2 it is not desirable since we would have to turn
**	the speaker on in order to make the timer count!  Normally one
**	sets counter 2 to mode 3 (square wave generator) to sound the
**	speaker.  You can set mode 2 (pulse generator) and the speaker
**	hardly makes any sound at all, a click when you turn it on and
**	a click when you turn it off.  Counter 0 should be safe if
**	we only read the counter bytes.
**
**	WARNING:  To use the hardware timer the way it really should be
**	used, we ought to capture it via a keyboard interrupt service
**	routine (ISR).	Otherwise, we may experience weaknesses in randomness
**	due to harmonic relationships between the hardware counter frequency
**	and the keyboard software polling frequency.  Unfortunately, this
**	implementation does not currently use keyboard interrupts to
**	capture the counter.  This is not a problem if we don't use the
**	hardware counter, but instead use the software counter fastcounter.
**	Thus, the hardware counter should not be used at all, unless we
**	support it with an ISR.
*/
	unsigned short t ;
	/* See if timer has been latched by kbisr(). */
	if (!timer_latched) /* The timer was not already latched. */
		kbisr();	/* latch timer */
	/* return latched timer and clear latch */
	t = ( 	(((unsigned short) latched_hitimer) << 8) |
		 ((unsigned short) latched_lotimer)
		) >> 1 ;
	timer_latched = FALSE;
	return (t) ;
}	/* pctimer0 */

#endif	/* ifdef USEPCTIMER */


void capturecounter(void)
/*	Push a fast counter on the random stack.  Should be called when
**	the user touches a key or clicks the mouse.
*/
{
	static unsigned int accum = 0;
	static byte abits = 0;	/* number of accumulated bits in accum */

#ifdef USEPCTIMER	/* we will use fast hardware timer on IBM PC */
#define cbits 8		/* number of bits of counter to capture each time */
	fastcounter += pctimer0();
#else			/* no fast hardware timer available */
#define cbits 4		/* number of bits of counter to capture each time */
#endif	/* ifdef USEPCTIMER */
#define cbitsmask ((1 << cbits)-1)

	accum = (accum << cbits) | (unsigned int) (fastcounter & cbitsmask);
	abits += cbits;
	while (abits >= 8) 
	{	if (randcount < sizeof(randpool))
			/* take lower byte of accum */
			randpool[randcount++] = accum;
		abits -= 8;
		accum >>= 8;
	}
	fastcounter = 0;
#undef cbitsmask
}	/* capturecounter */


/* Because these truly random bytes are so unwieldy to accumulate,
   they can be regarded as a precious resource.  Unfortunately,
   cryptographic key generation algorithms may require a great many
   random bytes while searching about for large random prime numbers.
   Fortunately, they need not all be truly random.  We only need as
   many truly random bytes as there are bytes in the large prime we
   are searching for.  These random bytes can be recycled and modified
   via pseudorandom numbers until the key is generated, without losing
   any of the integrity of randomness of the final key.
*/


static void randstir(void)
/* Stir up the recycled random number bin, via a pseudorandom generator */
{	int i;
	i = recyclecount;
	while (i--)
		recyclepool[i] ^= (byte) pseudorand();
	DEBUGprintf2(" Stirring %d recycled bytes. ",recyclecount);
}	/* randstir */


short randload(short bitcount)
/*	Flushes stale recycled random bits and copies a fresh supply of raw 
	random bits from randpool to recyclepool.  Returns actual number of 
	bits transferred.  Formerly named randrecycle. */
{	int bytecount;
	bytecount = (bitcount+7)/8;
	bytecount = min(bytecount,randcount);
	randflush();	/* reset recyclecount, discarding recyclepool */
	while (bytecount--)
		recyclepool[recyclecount++] = randpool[--randcount];
	DEBUGprintf2("\nAllocating %d recycleable random bytes. ",recyclecount);
	return(recyclecount*8);
}	/* randload */


void randflush(void)	/* destroys pool of recycled random numbers */
/* Ensures no sensitive data remains in memory that can be recovered later. */
{	recyclecount = sizeof (recyclepool);
	while (recyclecount)
		recyclepool[--recyclecount]=0;
	/* recyclecount is left at 0 */
	recycleptr = 0;
}	/* randflush */


short randombyte(void)
/*	Returns truly random byte from pool, or a pseudorandom value
**	if pool is empty.  It is recommended that the caller check
**	the value of randcount before calling randombyte.
*/
{	
	/* First try to get a cheap recycled random byte, if there are any. */
	if (recyclecount)	/* nonempty recycled pool */
	{	if (++recycleptr >= recyclecount)	/* ran out? */
		{	recycleptr = 0;	/* ran out of recycled random numbers */
			randstir();	/* stir up recycled bits */
		}
		return (recyclepool[recycleptr]);
	}

	/* Empty recycled pool.  Try a more expensive fresh random byte. */
	if (randcount)	/* nonempty random pool--return a very random number */
		return (randpool[--randcount]);

	/* Alas, fresh random pool is empty.  Get a pseudorandom byte.
	   Pseudorandom numbers are risky for cryptographic applications.
	   Although we will return a pseudorandom byte in the low order byte,
	   indicate error by making the result negative in the high byte.
	*/
	/* DEBUGprintf1("\007Warning: random pool empty! "); */
	return ( (pseudorand() & 0xFF) ^ (-1) );
}	/* randombyte */


static short keybuf = 0;	/* used only by keypress() and getkey()	*/

boolean keypress(void)	/* TRUE iff keyboard input ready */
{	/* Accumulates random numbers by timing user keystrokes. */
	static short lastkey = 0; /* used to detect autorepeat key sequences */
	static short next_to_lastkey = 0; /* allows a single repeated key */

#ifndef USEPCTIMER	/* no fast hardware timer available */
	fastcounter++;	/* used in lieu of fast hardware timer counter */
#endif	/* ifndef USEPCTIMER */

	if (keybuf & 0x100)	/* bit 8 means keybuf contains valid data */
		return( TRUE );	/* key was hit the last time thru */

	if (kbhit() == 0)	/* keyboard was not hit */
		return( FALSE );

	keybuf = getch() | 0x100; /* set data latch bit */

	/* Keyboard was hit.  Decide whether to call capturecounter... */

	/*  Guard against typahead buffer defeating fastcounter's randomness.
	**  This could be a problem for multicharacter sequences generated
	**  by a function key expansion or by the user generating keystrokes
	**  faster than our event loop can handle them.  Only the last 
	**  character of a multicharacter sequence will trigger the counter
	**  capture.  Also, don't let the keyboard's autorepeat feature
	**  produce nonrandom counter capture.  However, we do allow a 
	**  single repeated character to trigger counter capture, because
	**  many english words have double letter combinations, and it's 
	**  unlikely a typist would exploit the autorepeat feature to
	**  type a simple double letter sequence.
	*/

	if (kbhit() == 0)	/* nothing in typahead buffer */
	{	/* don't capture counter if key repeated */
		if (keybuf != lastkey)
			capturecounter(); /* save current random number seed */
		else if (keybuf != next_to_lastkey) /* allow single repeat */
			capturecounter();
		next_to_lastkey = lastkey;
		lastkey = keybuf;
	}
	return( TRUE );
}	/* keypress */


short getkey(void)	/* Returns data from keyboard (no echo). */
{	/* Also accumulates random numbers via keypress(). */
	while(! keypress() );		/* loop until key is pressed. */
	return( keybuf &= 0xff);	/* clear latch bit 8 */
}	/* getkey */


#define BS 8	/* ASCII backspace */
#define CR 13	/* ASCII carriage return */
#define LF 10	/* ASCII linefeed */


int getstring(char *strbuf, int maxlen, boolean echo)
/*	Gets string from user, with no control characters allowed.
	Also accumulates random numbers by calling getkey().
	maxlen is max length allowed for string.
	echo is TRUE iff we should echo keyboard to screen.
	Returns null-terminated string in strbuf. 
*/
{	short i;
	char c;
	i=0;
	while (TRUE)
	{	c = getkey();
	 	if (c==BS) 
		{	if (i) 
			{	if (echo) 
				{	fputc(BS,stderr);
					fputc(' ',stderr);
					fputc(BS,stderr);
				}
				i--;
			}
			continue;
		}
	 	if (echo) fputc(c,stderr);
		if (c==CR) 
		{	if (echo) fputc(LF,stderr);
			break;
		}
		if (c==LF)
			break;
		if (c=='\n')
			break;
		if (c<' ')	/* any ASCII control character */
			break;
		strbuf[i++] = c;
		if (i>=maxlen) 
		{	fprintf(stderr,"\007*\n");	/* -Enough! */
			while (keypress())
				getkey();	/* clean up any typeahead */
			break;
		}
	}
	strbuf[i] = '\0';	/* null termination of string */
	return(i);		/* returns string length */
}	/* getstring */


void randaccum(short bitcount)	/* Get this many random bits ready */
/* We will need a series of truly random bits for key generation.
   In most implementations, our random number supply is derived from
   random keyboard delays rather than a hardware random number
   chip.  So we will have to ensure we have a large enough pool of
   accumulated random numbers from the keyboard.  Later, randombyte
   will return bytes one at a time from the accumulated pool of
   random numbers.  For ergonomic reasons, we may want to prefill
   this random pool all at once initially.  This routine prefills
   a pool of random bits. */
{	short nbytes;
	char c;
	nbytes = min((bitcount+7)/8,sizeof(randpool));

	if (randcount < nbytes)	/* if we don't have enough already */
	{	fprintf(stderr,"\nWe need to generate %d random bytes.  This is done by measuring the",
			nbytes-randcount);
		fprintf(stderr,"\ntime intervals between your keystrokes.  Please enter some text on your");
		fprintf(stderr,"\nkeyboard, at least %d nonrepeating keystrokes, until you hear the bell:\n",
			(8*(nbytes-randcount)+cbits-1)/cbits);
		while (randcount < nbytes) 
		{	c=getkey();
			fputc(c,stderr);
			if (c==CR) fputc(LF,stderr);
		}
		fprintf(stderr,"\007*\n-Enough, thank you.\n");
		while (keypress()) getkey();	/* clean up any typeahead */
	}	/* if (randcount < nbytes) */
}	/* randaccum */

