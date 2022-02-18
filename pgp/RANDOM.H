/*	random.h - Header include file for random.c
	Last revised 15 Dec 90
	(c) 1989 Philip Zimmermann.  All rights reserved.
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
#ifndef min	/* if min macro not already defined */
#define min(a,b) ( (a)<(b) ? (a) : (b) )
#define max(a,b) ( (a)>(b) ? (a) : (b) )
#endif	/* if min macro not already defined */


int pseudorand(void);	/* 16-bit LCG pseudorandom generator */

/* Don't define PSEUDORANDOM unless you want only pseudorandom numbers */

#ifdef PSEUDORANDOM		/* use pseudorandom numbers */
#define randombyte()  ((byte) pseudorand())	/* pseudorandom generator */
#define randaccum(bitcount)		/* null function */
#define randload(bitcount)	/* null function */
#define randflush()		/* null function */
#define capturecounter()	/* null function */
#define keypress() kbhit()	/* TRUE iff keyboard input ready */
#define getkey() getch()	/* returns data from keyboard (no echo). */
#endif	/* ifdef PSEUDORANDOM */

#ifndef PSEUDORANDOM		/* use truly random numbers */

extern int randcount;	/* number of random bytes accumulated in pool */

void capturecounter(void); /* capture a fast counter into the random pool. */
/* Should be called when the user clicks the mouse, or from getkey(). */

short randombyte(void);	/* returns truly random byte from pool */

int getstring(char *strbuf,int maxlen,boolean echo);

void randaccum(short bitcount);	/* get this many raw random bits ready */

short randload(short bitcount);
/* Get fresh load of raw random bits into recyclepool for key generation */

void randflush(void);	/* flush recycled random bytes */

boolean keypress(void);	/* TRUE iff keyboard input ready */
short getkey(void);		/* returns data from keyboard (no echo). */

#endif			/* ifndef PSEUDORANDOM */

