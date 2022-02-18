/*
**	include file for memory manager routines
**	(c) 1988 Philip Zimmermann
*/

/* Elaborate protection mechanisms to assure no redefinitions of types...*/
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

typedef byte *ptr;		/* pointer type definition */

#define nil (void *)0		/* nil pointer */
#ifndef NULL
#define NULL (void *)0		/* nil pointer--UNIX nomenclature */
#endif

typedef unsigned short p_range;	/* values are 0-65536 */
/*	Note that the p_range type may be expanded to 32 bits 
	for larger partitions, if 64K is not big enough.
*/

/*
**	partsize - returns size of partition in bytes
**	Used to declare storage for a memory partition array of bytes.
**	Computed from the block size, the number of blocks, plus overhead.
*/
/* alignptr operator aligns storage to ptr boundary */
#define alignptr(bsize) ( (((bsize)+sizeof(ptr)-1)/sizeof(ptr))*sizeof(ptr) )
/* partheadsize is overhead storage required for partition */
#define partheadsize alignptr(sizeof(ptr)+sizeof(short))
#define	partsize(bsize,nblocks) (alignptr(bsize)*(nblocks)+partheadsize)

void pcreat2(ptr part, word16 bsize, word16 nblocks);
	/* Initialize a memory manager partition. */

/* pcreate is similar to pcreat2, but with slightly different arguments. */
#define pcreate(part,psize,bsize) \
	pcreat2(part,alignptr(bsize),(psize-partheadsize)/alignptr(bsize))

#ifndef _NOMALLOC	/* malloc library routine available */
ptr partalloc(word16 bsize, word16 nblocks);
	/* Allocate and initialize a memory partition. */
#endif

ptr gblock(register ptr part);
	/* Get a memory block from partition. */

ptr rblock(register ptr part, register ptr addr);
	/* Release a memory block to partition. */

#ifndef _NOPRINTF	/* printf available */
void dumpfree(ptr part);
	/* Dump partition free list in hex. */
#endif

