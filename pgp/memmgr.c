/***
	Begin memory management routines:  pcreat2, gblock, and rblock. 
	Assumes fixed sized blocks.  This approach produces no memory
	fragmentation, and requires no garbage collection.  This feature
	is important in a real-time environment.

	(c) 1988 Philip Zimmermann
	Boulder Software Engineering
	3021 Eleventh Street
	Boulder, CO 80304
	(303) 444-4541

	31 July 88
	Revised 15 Dec 90
***/

/* #define _NOPRINTF	/* define if no printf available */
#ifndef _NOPRINTF
#include <stdio.h>	/* for printf(), puts() */
#endif
/* Define whether malloc is available.  Some embedded systems lack it. */
/* #define _NOMALLOC */ /* define if no malloc is available. */
#ifndef _NOMALLOC	/* malloc library routine available */
#include <stdlib.h>	/* ANSI C library - for malloc() and free() */
/* #include <alloc.h> */	/* Borland Turbo C has malloc in <alloc.h> */
#endif	/* malloc available */

#include "memmgr.h"	/* memory manager headers */

#define putstr(s) puts(s) /* put string */

/*	gblock and rblock contain critical sections of code that should not
	be interrupted by any other process that might use the same data
	structure.  We protect this critical code by disabling interrupts.
	The primitives for this are begin_critical_section() and 
	end_critical_section().  These are necessarily machine-dependent 
	primitives, and are only needed in multitasking or interrupt-
	driven realtime environments.  For non-realtime environments, 
	stubs are provided here for these primitives.
*/
#define begin_critical_section()	/* null stub */
#define end_critical_section()	/* null stub */

/* This typedef for a memory partition is unused, but is here for clarity */
typedef struct	/* memory manager partition structure */
{	ptr head;	/* ptr to head of free list */
	p_range psize;	/* partition size, as measured in bytes */
	byte body;	/* body of memory partition starts here */
} partition;


/*
**	partsize - returns size of partition in bytes
**	Used to declare storage for a memory partition array of bytes.
**	Computed from the block size, the number of blocks,
**	plus partheadsize.
**
**	partheadsize is a #define in the header file "memmgr.h"
**	partsize() is a #define in the header file "memmgr.h"
*/


/*
**	pcreate - initialize memory manager partition
**	Similar to pcreat2, but with slightly different arguments.
**
**	pcreate() is a #define in the header file "memmgr.h"
*/


/*
**	pcreat2 - initialize memory manager partition
**
**	Create a linked list of fixed-sized free memory blocks.
**	Note that the link field of each block has meaning only when the
**	block is in the list of deallocated blocks.
**	If invoked in a real-time environment, we assume this entire 
**	routine is executed without interruption.
*/
void pcreat2(ptr part, word16 bsize, word16 nblocks)
/*	part is pointer to memory partition, better if aligned 
	to ptr boundary.
	bsize is block size, must be ptr aligned.
	nblocks is number of blocks.
*/
{	ptr link;		/* scratch pointer */
	p_range * psize;	/* pointer to partition size */
	psize = (p_range *) (part + sizeof(ptr));
	*psize = partsize(bsize,nblocks);
	link = part + partheadsize; /* address of 1st block */
	*(ptr *) part = link;	/* point head at 1st block */

	while (nblocks--)
	{	part = link;		/* skip to next block */
		/* compute addr of next block */
		link += bsize;		/* compute addr of next block */
		*(ptr *) part = link;	/* create link to it */
	}
	*(ptr *) part = nil;	/* last link in chain is nil */
}	/* pcreat2 */

#ifndef _NOMALLOC	/* malloc library routine available */
/*
**	partalloc - allocate and initialize memory manager partition
**	Returns a ptr to the initialized partition, or NULL if there's no room.
**	Can be called instead of pcreat2, if the storage needs allocating.
**	If invoked in a real-time environment, we assume this entire 
**	routine is executed without interruption.
*/
ptr partalloc(word16 bsize, word16 nblocks)
/*	bsize is block size.
	nblocks is number of blocks.
*/
{	ptr *part;
	/* allign block size to ptr boundary */
	bsize = alignptr(bsize);
	/* allocate memory partition... */
	part = (ptr *) malloc(partsize(bsize,nblocks));
	if (part != NULL)	/* if memory is not exhausted... */
		pcreat2((ptr) part,bsize,nblocks);
	return ((ptr) part);
} /* partalloc */
#endif	/* ifndef _NOMALLOC */

/*
**	gblock - get memory block from partition
**
**	Delink a block from the head of the linked list of free blocks.
*/
ptr gblock(register ptr part)
/*	part is pointer to memory partition. */
{	register ptr link;	/* scratch pointer */
	begin_critical_section();	/* prevent interruption */
	link = *(ptr *) part;	/* get head of free list */
	if (link != nil)	/* list exhausted if head is nil */
		*(ptr *) part = *(ptr *) link; /* update head */
#ifdef DEBUG
	else	putstr("\nGblock warning: memory partion exhausted!\07\n");
#endif /* DEBUG */
	end_critical_section();
	return (link);		/* return address of memory block or nil */
	/* Note that this allocated block's link field is now trashable. */
}	/* gblock */


/*
**	rblock - release memory block to partition
**
**	Insert a block at the head of the linked list of free blocks.
*/
ptr rblock(register ptr part, register ptr addr)
/*	part is pointer to memory partition.
	addr is pointer to block--must belong to partition.
*/
{	register ptr link;	/* scratch pointer */
#ifdef DEBUG
	{	p_range * psize;	/* pointer to partition size */
		psize = (p_range *) (part + sizeof(ptr));
		if ( ( addr > (part + *psize) )
		  || ( addr < (part + partheadsize) ) )
		{	if (addr==nil)	/* special case diagnostic */
				putstr("\nRblock warning: nil memory block pointer\07\n");
			else
				putstr("\nRblock error: memory block not in partition!\07\n");
			return (addr);	/* return ptr unmodified */
		}
	}
#endif /* DEBUG */
	begin_critical_section();	/* prevent interruption */
	link = *(ptr *) part;	/* save old head of free list */
	*(ptr *) addr = link;	/* point released block at old head */
	*(ptr *) part = addr;	/* point head at released block */
	end_critical_section();
	return (nil);		/* normal return--nil ptr */
}	/* rblock */


#ifndef _NOPRINTF	/* printf available */
/*
**	dumpfree - dump a partition's free block list in hex.
**	If invoked in a real-time environment, we assume this entire 
**	routine is executed without interruption.
*/
void dumpfree(ptr part)
/*	part is pointer to memory partition. */
{	byte i;
	p_range * psize;	/* pointer to partition size */
	psize = (p_range *) (part + sizeof(ptr));
	i = 0;
	printf("\nMemory partition at %04X, size=%04X ",part,*psize);
	while ((*(ptr *)part)!=nil)		/* go until we hit a nil ptr */
	{	if ((i-- & 7)==0) putchar('\n');
		printf("%04X ",*(ptr *)part);	/* print a pointer */
		part = *(ptr *)part;		/* follow chain */
	}
	putstr("nil\n");
} /* dumpfree */
#endif	/* ifndef _NOPRINTF */


