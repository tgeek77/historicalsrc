/*	basslib.c  --  BassOmatic encipherment functions in C.
	Version 1.0  25 Jun 89 - Last revised 22 May 91

	(c) Copyright 1988 by Philip Zimmermann.  All rights reserved.  
	This software may not be copied without the written permission of 
	Philip Zimmermann.  The author assumes no liability for damages
	resulting from the use of this software, even if the damage results
	from defects in this software.  No warranty is expressed or implied.

	Boulder Software Engineering
	3021 Eleventh Street
	Boulder, CO 80304  USA
	Tel. (303) 444-4541
	FAX (303) 444-4541 ext. 10

	BassOmatic is a conventional block cipher with a 256-byte
	block size for the plaintext and the ciphertext.  It also
	uses a key size of up to 256 bytes.  It runs fairly quickly
	on a computer, faster than most simple DES implementations.
	Like the DES, it can be used in cipher feedback and cipher block 
	chaining modes.  It is based in part on Charles W. Merritt's 
	algorithms which have been used in secure military communications.
	Merritt's original designs were refined by Zhahai Stewart and
	Philip Zimmermann to improve security and to improve performance
	in a portable C implementation.  BassOmatic has not yet (in 1989) 
	been through a formal security review and has had only limited peer 
	review.  The initial version was implemented in Microsoft C for the
	IBM PC, and it has been ported to MPW C on the Apple Macintosh 
	and to Unix C without significant modification.

	BassOmatic gets its name from an old Dan Aykroyd Saturday Night Live 
	skit involving a blender and a whole fish.  The BassOmatic algorithm 
	does to data what the original BassOmatic did to the fish.
*/

/* Define STATIC as blank to assist execution performance profiling. */
#define STATIC static	/* define STATIC as static for normal use */

#include <stdio.h>	/* for printf */

#include "memmgr.h"	/* memory manager headers */
#include "lfsr.h"	/* Linear Feedback Shift Register headers */
#include "basslib.h"	/* BassOmatic headers */

/* on many CPUs, using 16 bits for bytecounter is actually faster: */
#define bytecounter word16 /* byte, or word16 for speed */

#ifdef DEBUG
#define DEBUGprintf1(x) fprintf(stderr,x)
#define DEBUGprintf2(x,y) fprintf(stderr,x,y)
#else
#define DEBUGprintf1(x)	/* null macro */
#define DEBUGprintf2(x,y)	/* null macro */
#endif


#define NCONTEXTS 3		/* number of key contexts allowed at once */
	/* NUMBLOX is number of memory blocks in partition */
#define NUMBLOX (NCONTEXTS*(NTABLES+3)+8)
/* declare memory partition buffer space */
static byte part[partsize(256,NUMBLOX)]; /* memory partition */
/* We could just call calloc() for this space, instead of declaring it here. */

/* The following variables comprise the keyed context information for the
** BassOmatic machine.  If the BassOmatic is rekeyed, these variables
** will be affected.  If more than one BassOmatic key context is needed
** concurrently, these variables must be saved and restored for each
** context change.
*/

static boolean initialized = FALSE; /* determines whether key context is defined */
static byteptr tlist[NTABLES] = {nil};	/* list of permutation table pointers */
static byte bitmasks[NTABLES];	/* bitshredder bitmasks with 50% bits set */

static byteptr iv = nil; /* CFB Initialization Vector used by initcfb and basscfb */
static boolean cfbuncryp = FALSE; /* TRUE means decrypting (in CFB mode) */
static boolean uncryp = FALSE;	/* TRUE means decrypting (in ECB mode) */
/* The following parameters are computed from the key control byte...*/
static char nrounds = 0;	/* specifies number of rounds thru BassOmatic */
static boolean hardrand = FALSE; /* means regenerate tables with BassOmatic */
static boolean shred8ways = FALSE; /* means use 8-way bit shredding */
static boolean rerand = FALSE;	/* means replenish tables with every block */

static byteptr lfsr = nil;	/* it would help to align LFSR on 256-byte boundary */
			/* rtail is an index into LFSR buffer */
static byte rtail = 0;	/* points to 256, which is same as 0 */

/* End of BassOmatic keyed context variables */



/*
**	fillbuf(dst,count,c) - fill byte buffer dst with byte c
**		dst is destination buffer pointer.
**		count is nonzero byte count.
**		c is fill byte.
*/
void fillbuf(register byteptr dst, register short count, register byte c)
{	do *dst++ = c; while (--count);
} /* fillbuf */


/*
**	CRC routines are purely for debugging purposes...
*/
#define CRCDEBUG	/* enables CRC debugging code */
#ifdef CRCDEBUG
/*
**	updcrc - updates CRC 16-bit accumulator with ch,
**	uses CCITT polynomial:  X^16 + X^12 + X^5 + 1
*/
static word16 updcrc(byte ch, word16 crcaccum)
{	word16 shifter,flag,data;
	data = ((word16) ch) & 0xff;
	for (shifter = 0x80; shifter; shifter >>= 1)
	{	flag = (crcaccum & 0x8000);
		crcaccum <<= 1;
		crcaccum |= ((shifter & data) ? 1 : 0);
		if (flag) crcaccum ^= 0x1021;
	}
	return (crcaccum & 0xffff);
}	/* updcrc() */


/*
**	crc() - compute crc of buffer
**	Used for diagnostic purposes.
*/
word16 crc(register byteptr buf, int count)
{	word16 crcaccum;	/* CRC accumulator */
	crcaccum = 0;		/* clear crc accumulator */
	do	crcaccum = updcrc(*buf++,crcaccum);
	while (--count);	/* loop 256 times */
	crcaccum = updcrc(0,crcaccum);	/* finish up crc */
	crcaccum = updcrc(0,crcaccum);	/* have to do it twice */
	return(crcaccum);	/* return 16-bit CRC */
} /* crc */


#define dumpcrc(msg,buf) printf("%s CRC=%04x ",msg,crc(buf,256))

/*
**	dumpblock - dump 256-byte buffer in hex
*/
static void dumpblock(byteptr buf)
{	bytecounter i;
	i = 256;
	printf(" Memory block at %04X: ",buf);
	do
	{	if ((i & 15)==0)
			putchar('\n');
		printf("%02X ",*buf++);
	} while (--i);	/* loop 256 times */
	dumpcrc("",buf-256);
	putchar('\n');
} /* dumpblock */

#endif	/* end of CRC debugging routines */


/*
**	randbuf and randbuf_counter are used by initbassrand, initbrand, 
**	bassrand, and closebrand.  They are not directly used by the BassOmatic
**	routines except by initkey(), and thus are not considered part of a 
**	lasting key context.  
*/
static byteptr randbuf = nil; /* buffer for BassOmatic random # generator */
static byte randbuf_counter = 0;	/* # of random bytes left in randbuf */

/*
**	initbrand - initialize bassrand, BassOmatic random number generator
**		For internal use by initkey() only.
**		seed is pointer to random number seed buffer.
**		seedlen is length of seed buffer, must be <= 256.
*/
static void initbrand(byteptr seed, short seedlen)
{	short i;
	if (randbuf==nil)
		randbuf = (byteptr) gblock(part);	/* allocate block */

	if (seedlen > 256) seedlen=256;
	for (i=0; i<seedlen; i++) /* copy original seed material to randbuf */
		randbuf[i] = seed[i];

	/* fill rest of randbuf with randomly modified key material */
	for (; i<256; i++)	/* pick up where we left off */
		randbuf[i] = getlfsr(lfsr,rtail); /* macro gets LFSR byte */

	randbuf_counter = 0;		/* # of random bytes left in randbuf */
} /* initbrand */


/*
**	initbassrand - initialize bassrand, BassOmatic random number generator
**		This can be used for generating cryptographically strong random 
**		numbers by any external application code outside the BassOmatic.
**		key is pointer to BassOmatic key buffer.
**		keylen is length of key buffer, must be < 256.
**		seed is pointer to random number seed buffer.
**		seedlen is length of seed buffer, must be <= 256.
**
**		NOTE:  Because this routine calls initkey(), this generator 
**		must be closed by calling closebass(), NOT closebrand().
*/
void initbassrand(byteptr key, short keylen, byteptr seed, short seedlen)
{	short i;
	if (randbuf==nil)	/* prevents multiple initialization */
	{	initkey(key, keylen, FALSE);	/* initialize BassOmatic */
		randbuf = (byteptr) gblock(part);	/* allocate block */
	}
	fillbuf(randbuf,256,0);		/* get a clean start */
	if (seedlen > 256) seedlen=256;
	for (i=0; i<seedlen; i++)	/* copy original seed material to randbuf */
		randbuf[i] = seed[i];
	randbuf_counter = 0;		/* # of random bytes left in randbuf */
} /* initbassrand */


/*
**	bassrand - BassOmatic pseudo-random number generator
**		This can be used for generating cryptographically strong random 
**		numbers by any external application code outside the BassOmatic.
*/
byte bassrand(void)
{	byteptr tmp;
	if (randbuf_counter==0)	/* if random buffer is spent...*/
	{	tmp = (byteptr) gblock(part);	/* allocate new block */
		bassomatic(randbuf,tmp); /* fill new block */
		rblock(part,randbuf);	/* release old spent block */
		randbuf = tmp;		/* start on new block */
	}
	return(randbuf[--randbuf_counter]);	/* take a byte from randbuf */
} /* bassrand */


/*
**	closebrand - deallocate storage used by bassrand
**		For internal use by initkey() only.
*/
static void closebrand(void)
{	if (randbuf!=nil)
		randbuf = rblock(part,randbuf);	/* release block */
} /* closebrand */


/*
**	buildtbl - build a random byte permutation vector
**
**	References context variables lfsr, rtail, and part.
**
**	A permutation vector is a table of 256 bytes containing the
**	values 0-255 in random order.  Each of the values 0-255 appears
**	exactly once in the table, with no duplicates and no omissions.
**
**	The appropriate way to build such a table for cryptographic
**	applications is to do the following:
**	1) Start with an empty table, meaning its length is zero.
**	2) Use a pseudo-random number generator to generate random bytes
**	   that are appended to the table if and only if they are not
**	   already in the table.  If the random byte is already in the
**	   table, it is discarded and another one is generated from the
**	   pseudo-random number generator.  As the table gets nearly full,
**	   more and more random bytes are discarded as duplicate entries.
**	   This is continued until 256 bytes have been inserted in the table.
**
**	While this approach seems computationally wasteful, it makes it harder
**	for a cryptanalyst to infer the properties of the pseudo-random number
**	generator, because so many of its output bytes are discarded.
**
**	Permutation vectors such as these are useful for byte substitution
**	tables and byte transposition tables.  These are also referred to
**	herein as key schedule tables.
*/
STATIC void buildtbl(register byteptr table, boolean rselect)
/*	table is pointer to table to build.
	rselect is to select which of 2 random number generators to use.
*/
{	register byteptr notdup;	/* scratchpad bitmap */
	register byte c;
	register short tlen;	/* current accumulated table length */ 
	register short randtics; /* counts LFSR tics */
#define MAXTICS 16383		/* lose patience with LFSR after this long */
	notdup = (byteptr) gblock(part); /* we could use local stack array instead. */
	fillbuf(notdup,256,TRUE); /* initialize scratchpad bitmap */
	tlen = 0;		/* start new table with length 0 */
	/* To fill one table, we can expect to have to tic the LFSR
		typically about 1000-2500 times, on the average. */
	randtics = MAXTICS;	/* countdown maximum LFSR tics */
	do
	{	/* get pseudo-random byte from either LFSR or BassOmatic... */
		c = rselect ?
			bassrand() :		/* get a hard random byte */
			getlfsr(lfsr,rtail);	/* macro gets LFSR byte */
		if (notdup[c]) 	/* not in table already? */
		{	table[tlen++] = c; /* append it */
			notdup[c] = FALSE; /* indicate it's now in table */
		}
		if (--randtics == 0)  /* detects bogus random generator */
		{	/* Must be an LFSR problem, because the bassrand
				generator will probably always run OK, so we
				won't even check rselect. */
			DEBUGprintf1("\007Adjusting weak LFSR. ");
			stomplfsr(lfsr); /* hit unruly LFSR upside the head */
			randtics=MAXTICS;	/* reset countdown counter */
		} /* randtics alarm */
	} while (tlen<256); /* do until table is full */
	if (!rselect)
	/*	"discard" current contents of lfsr buffer. Causes
		steplfsr256 to be called the next time getlfsr is called. */
		rtail=0;	/* dump some LFSR output, confuse attacker */
	rblock(part,notdup);	/* deallocate storage */
} /* buildtbl */


/*
**	Some notes--
**
**	With some sacrifice of performance due to bit packing and unpacking, 
**	it would be possible to modify the whole BassOmatic algorithm to use 
**	a smaller block size.  This would require using smaller key schedule 
**	tables with smaller entries.  For example, you could use a table of 
**	16 4-bit entries instead of 256 8-bit entries.  The number of bits in 
**	each table entry exponentialy determines the number of entries in the 
**	key schedule table, and those two dimensions together determine the 
**	size of the plaintext or ciphertext block.  The following chart 
**	summarizes the relationship between table entry width and cipher 
**	block size.
**
**	ENTRY       TABLE           BLOCK
**	WIDTH       LENGTH          SIZE
**	-----       ------          -----
**	8 bits      256 entries     2048 bits, or 256 bytes
**	7 bits      128 entries		896 bits, or 112 bytes
**	6 bits      64 entries      384 bits, or 48 bytes
**	5 bits      32 entries      160 bits, or 20 bytes
**	4 bits      16 entries      64 bits, or 8 bytes
**
**
**	Other questions--
**	How many of the key bits are actually effective in producing the
**	key schedule tables?  Are any key bits wasted?
**
**	There are 256! permutation tables possible.  With 8 tables made
**	from a single key, there are (256!)**8 sets of tables possible.
**	If there are n bytes in a key (with n<=256), there are 256**n
**	keys possible.
**
**	In theory, more than one of these keys can produce the same table 
**	or set of tables, since a different selection of random output 
**	bytes from the pseudorandom number generator may be discarded to 
**	produce the same table.
*/


/*
**	invert - invert a random permutation table
**	Called from bldtbls.
*/
STATIC void invert(register byteptr intable, register byteptr outtable)
{	register byte i;
	i = 0;		/* byte loop index i = 0,255,254,...2,1 */
	do	outtable[intable[i]] = i; /* invert table */
	while (--i);	/* loop 256 times */
}	/* invert */


/*
**	transpose - transpose input via table to output
**	Called from bldtbls.
*/
STATIC void transpose(register byteptr in, register byteptr out, register byteptr table)
/*	in and out are the input, output blocks, 256 bytes each.
	table contains random permutation of 256 bytes.
*/
{	register byte i;
	i = 256;	/* byte loop counter */
	do	*out++ = in[*table++];	/* table transpose */
	while (--i);	/* loop 256 times */
}	/* transpose */


/*
**	halfmask(c) - returns TRUE iff 50% of the bits in c are set.
**	Called only from getmask.
*/
STATIC boolean halfmask(byte c)
{	byte bitmask,nbits;
	nbits=0; bitmask=0x80;
	do 
	{	if (c & bitmask) 
			nbits++; /* count the # of 1 bits */
		bitmask >>= 1;
	} while (bitmask);
	return(nbits==4);	/* are 4 out of 8 bits set? */
} /* halfmask */


/*
**	getmask - search table for a suitable random mask byte.
**	Finds a random mask byte with 50% of its bits set.
**	Called from bldtbls.
*/
STATIC byte getmask(register byteptr table)
/* 	table contains random permutation of 256 bytes. */
{	byte i;
	i = 0;		/* byte loop index i = 0,255,254,...2,1 */
	do
	{	if (halfmask(table[i]))
			return(table[i]); /* returns 1st 50% bitmask found */
	} while (--i);	/* loop 256 times */
	return (0x0f);		/* never gets here */
}	/* getmask */


#define ptrswap(p1,p2) { register byteptr p3; p3=p1; p1=p2; p2=p3; }


/*
**	bldtbls - generate all the permutation tables for the BassOmatic
**
**	References context variables tlist, shred8ways, bitmasks, and part.
*/
STATIC void bldtbls(boolean hardrand, boolean decryp)
/*	hardrand specifies which random number generator to use.
	decryp determines whether to invert the tables.
*/
{	byteptr tmp;	/* scratchpad table pointers */
	byteptr mixer;	/* table transposer */
	byte i;
	tmp = (byteptr) gblock(part);	/* allocate new block */

	mixer = (byteptr) gblock(part);	/* allocate transposer table */
	buildtbl(mixer,hardrand);

	for (i=0; i<NTABLES; i++)		/* for each key schedule table */
	{	/* build a random byte permutation vector... */
		buildtbl(tmp,hardrand);
		if (!shred8ways) /* need bitmasks for 2-way bitshredding */
			bitmasks[i] = getmask(tmp);
		/* currently, tmp is the table we just built */
		transpose(tmp,tlist[i],mixer); /* mix up the table */
		/* now tlist[i] is the table we just built */
	}		/* for each table */

	rblock(part,mixer);	/* deallocate transposer table */

	/* For decryption, it's not safe to invert any tables until they've
	   all been built, in case hardrand is set.  Use separate loop... */
	if (decryp) /* decryption uses inverted tables */
		for (i=0; i<NTABLES; i++) 	/* for each table */
		{	invert(tlist[i],tmp);
			ptrswap(tlist[i],tmp); /* swap/replace block ptrs */
		}		/* for each table */
	rblock(part,tmp);	/* deallocate block */
	DEBUGprintf1("*");
} /* bldtbls */


/*
**	bass_save - saves BassOmatic key context in context structure
*/
void bass_save(KEYCONTEXT *context)
{	int i;
	context->initialized = initialized;
	for (i=0; i<NTABLES; i++)
		context->tlist[i] = tlist[i];
	for (i=0; i<NTABLES; i++)
		context->bitmasks[i] = bitmasks[i];
	context->iv = iv; /* note that iv was passed to initcfb by caller */
	context->cfbuncryp = cfbuncryp;
	context->uncryp = uncryp;
	context->nrounds = nrounds;
	context->hardrand = hardrand;
	context->shred8ways = shred8ways;
	context->rerand = rerand;
	context->lfsr = lfsr;
	context->rtail = rtail;
} /* bass_save */


/*
**	bass_restore - restore BassOmatic key context from context structure
*/
void bass_restore(KEYCONTEXT *context)
{	int i;
	initialized = context->initialized;
	for (i=0; i<NTABLES; i++)
		tlist[i] = context->tlist[i];
	for (i=0; i<NTABLES; i++)
		bitmasks[i] = context->bitmasks[i];
	iv = context->iv; /* note that iv was passed to initcfb by caller */
	cfbuncryp = context->cfbuncryp;
	uncryp = context->uncryp;
	nrounds = context->nrounds;
	hardrand = context->hardrand;
	shred8ways = context->shred8ways;
	rerand = context->rerand;
	lfsr = context->lfsr;
	rtail = context->rtail;
} /* bass_restore */


/*
**	closebass - end the current BassOmatic key context, freeing its buffers
*/
void closebass(void)
{	int i;
	if (initialized)
	{
		/* Close BassOmatic random number generator, in case it's open: */
		closebrand();

		for (i=0; i<NTABLES; i++)
			if (tlist[i]!=nil)
				tlist[i] = rblock(part,tlist[i]);
		/* Note that iv is not allocated from memory manager,
			and thus should not be deallocated */
		if (lfsr!=nil)
			lfsr = rblock(part,lfsr);
		initialized = FALSE;
	}
} /* closebass */


static char *copyright_notice(void)
/* force linker to include copyright notice in the executable object image. */
{ return ("(c)1988 Philip Zimmermann"); } /* copyright_notice */


/*
**	initkey - Initializes the BassOmatic key schedule tables via key.
**
**	References context variables from key context structure, all of them.
**
**	Uses several bits from the first byte of the key to select
**	how exhaustivly to run the BassOmatic.  The key control bits
**	specify what tradeoff to make between speed and security.
**	These bits in the first byte of the key have these meanings:
**	bits 0-2: Number of rounds thru BassOmatic (0-7 means 1-8
**		times through).  The greater the number, the slower
**		it runs.
**	bit 3:  Set to 1 if we should use slower 8-way bit shredding,
**		Set to 0 if we should use faster 50% bitmask shredding.
**	bit 4:	Set to 1 means use BassOmatic to build its own tables.
**	bit 5:  Set to 1 iff we should rebuild tables with every block.
**		This implicitly disables bit 4, above.
**	bits 6-7:  Reserved.
**
**	Key control bit 4 enables a two-tiered key schedule table
**	generation.  The first set of tables are generated in the usual
**	way with a linear feedback shift register (LFSR).  Then, a new
**	set of tables is regenerated with a far better pseudo-random
**	number generator--namely, the BassOmatic running off the first
**	set of tables.  The BassOmatic pseudo-random number generator
**	feeds its output back into itself to generate a stream of
**	random blocks.  It is seeded with the same raw key that
**	seeded the LFSR.  When the new set of tables are built, they
**	replace the first set as the working tables.
**
**	Key control bit 5 keeps running the pseudorandom number generator
**	to continuously rebuild the key schedule tables for each block of text.
**	It automatically turns off key control bit 4.  Continuously replenishing
**	the tables greatly slows down everything, but it improves security
**	significantly.  This mode unfortunately also makes using the BassOmatic
**	in the DES-like cipher block chaining (CBC) and cipher feedback (CFB)
**	modes non-self-synchronizing.
*/
int initkey(byteptr key, short keylen, boolean decryp)
/*	key is pointer to key buffer, up to 256 bytes long.
	keylen is length of key buffer, including key control byte.
	decryp is TRUE if decrypting, FALSE if encrypting.
*/
{	byte i;

	/* initialize BassOmatic data structures */
	static boolean partition_initialized = FALSE;
	if (!partition_initialized)
	{	/* if already initialized, skip these steps. */
		partition_initialized = TRUE;
		pcreat2(part,256,NUMBLOX); /* initialize memory partition */
#ifdef DEBUG2
		dumpfree(part);		/* dump memory free list */
#endif
	}

	if (key == nil) /* initkey(nil,0,0) only initializes partition */
		return(0);

	if (keylen < 2)
	{	/* key must have control byte and nonzero body length */
		fprintf(stderr,"\nError: BassOmatic key too short.\n\007");
		return(-1);	/* error return */
	}

	closebass();	/* deallocate any previously allocated buffers */

	initialized = TRUE;	/* set already initialized flag */
	for (i=0; i<NTABLES; i++)	/* for each table */
	{	/* get memory block from partition */
		tlist[i] = (byteptr) gblock(part);
	}		/* for each table */

	nrounds = (*key & 0x07) + 1; /* specifies number of rounds */
	shred8ways = ((*key & 0x08) != 0); /* use 8-way bit shredding? */
	rerand = ((*key & 0x20) != 0); /* replenish tables with every block */
	/* hardrand means use BassOmatic table generator... */
	hardrand = ((*key & 0x10) != 0) && !rerand;
	uncryp = FALSE;	/* initially assume encrypt, in case of hardrand */

#ifdef DEBUG3
	if (decryp)	/* use inverted tables for decryption */
		fprintf(stderr,"Decrypt, ");
	else		/* use non-inverted tables for encryption */
		fprintf(stderr,"Encrypt, ");
	fprintf(stderr,"%x rounds, ",nrounds);
	if (hardrand)	/* BassOmatic random number generator */
		fprintf(stderr,"hard ");
	else		/* LFSR random number generator */
		fprintf(stderr,"LFSR ");
	if (rerand)	/* rebuild tables for every block */
		fprintf(stderr,"dynamic ");
	else		/* keep same tables throughout message */
		fprintf(stderr,"static ");
	fprintf(stderr,"tables, ");
	
	if (shred8ways)
		fprintf(stderr,"8-way bitshred.\n");
	else
		fprintf(stderr,"2-way bitshred.\n");
#endif	/* DEBUG3 */

	/* init LFSR random number generator with key seed */
	if (lfsr==nil)
		lfsr = (byteptr) gblock(part); /* allocate LFSR buffer */
	if (keylen > 255) keylen=255;
	/* Assume actual key starts after 1st byte, which is control byte */
	initlfsr(key+1,keylen-1,lfsr,&rtail);
	/* dumpblock(lfsr); */

	buildtbl(tlist[0],FALSE); /* build throwaway table to prime the LFSR */

	/* generate all the permutation tables for the key schedule */
	if (!rerand)	/* don't do it now if it's going to be redone anyway */
		bldtbls(FALSE,decryp && !hardrand);

	/* if hardrand, rebuild tables again, this time with BassOmatic */
	if (hardrand)	/* rebuild tables with BassOmatic */
	{	/* form progressivly better bassrand function. */
		/* init BassOmatic pseudo-random generator */
		initbrand(key+1,keylen-1); /* skip 1st key byte */
		bldtbls(hardrand,decryp);/* generate all the tables again */
		closebrand();	/* deallocate scratch buffers for bassrand */
	} /* if (hardrand) */
	uncryp = decryp;	/* specifies BassOmatic decrypt or encrypt */

	if (!rerand)	/* if we don't need lfsr buffer anymore, then free it. */
		lfsr=rblock(part,lfsr); /* sure hope we don't use lfsr again */

	/* Do an explicit reference to the copyright notice so that the linker 
	   will be forced to include it in the executable object image... */
	copyright_notice();	/* has no real effect at run time */
	return(0);	/* normal return */
} /* initkey */


/* Now for the primitives called directly from the BassOmatic algorithm...*/


/*
**	shred1bit - 8-way random bit shred
**
**	Tears each byte into 8 bits, and randomly distributes the bits.
**	Uses 8 different permutation vectors from tlist.
**	Unfortunately, it always uses the same 8 tables.
*/
STATIC void shred1bit(register byteptr in, register byteptr out)
/*	in and out are input, output blocks, 256 bytes each. */
{	register byte bitmask;	/* byte has 1 of its bits set */
	register bytecounter i;
	register byteptr table;	/* permutation vector */
	byteptr insave;		/* for saving input buffer pointer */
	byte j;
	bitmask = 0x80;		/* initialize bitmask at highest bit */
	fillbuf(out,256,0);	/* make sure output buffer is clean */
	/* We could run faster by skipping the fillbuf step, and
	   using "=" instead of "|=" the first time thru the j loop below. */

	insave = in;		/* save input buffer pointer */
	for (j=0; j<=7; j++)	/* for each of 8 bits per byte */
	{	i = 256;	/* byte loop counter */
		table = tlist[j]; /* select a permutation vector */
		in = insave;	/* recover input buffer pointer */
		do	/* permute a single bit from each byte */
			out[*table++] |= (*in++ & bitmask);
		while (--i);	/* loop 256 times */
		bitmask >>= 1;	/* select next bit for isolation */
	}
}	/* shred1bit */


/*
**	shred4bit - 2-way random bit shred
**
**	Tears each byte in half, and randomly distributes the halves.
*/
STATIC void shred4bit(register byteptr in, register byteptr out, 
	register byteptr t1, register byteptr t2, register byte bitmask)
/*	in and out are input, output blocks, 256 bytes each.
	t1 and t2 each contain random permutation of 256 bytes.
	bitmask is byte which has 50% of its bits set.
*/
{	register bytecounter i;
	byteptr insave;		/* for saving input buffer pointer */
	insave = in;		/* save input buffer pointer */
	i = 256;		/* byte loop counter */
	do			/* isolate half the bits */
		out[*t1++] = *in++ & bitmask;
	while (--i);		/* loop 256 times */
	in = insave;		/* recover input buffer pointer */
	bitmask = ~bitmask;	/* invert bitmask for other half */
	i = 256;		/* byte loop counter */
	do		/* isolate other half and combine the two halfs */
		out[*t2++] |= *in++ & bitmask;
	while (--i);		/* loop 256 times */
}	/* shred4bit */


/*
**	multilookup - change input via multiple substitution tables
*/
STATIC void multilookup(register byteptr in, register byteptr out, byte ti)
/*	in and out are input, output blocks, 256 bytes each.
	ti contains index into starting point of tlist.
*/
{	register byteptr table;
	register byte i;
	byte j;
	j=8;
	do
	{	table = tlist[ti++ & 7];	/* assumes 8 tables */
		i=32;
		do	*out++ = table[*in++];	/* multi-table substitute */
		while (--i);	/* loop 32 times */
	}
	while (--j);	/* loop 8 times */
}	/* multilookup */


/*
**	xortable - change block via xor with random table
**
**	This function would serve as its own inverse, if the table is the 
**	same each time.  For use with an inverted table, call ixortable.
**	This function inverts 50% of the bits.
*/
STATIC void xortable(register byteptr block, register byteptr table)
/*	block is a 256 byte block.
	table contains random permutation of 256 bytes.
*/
{	register bytecounter i;
	i = 256;	/* byte loop counter */
	do	*block++ ^= *table++;	/* table xor */
	while (--i);	/* loop 256 times */
}	/* xortable */


/*
**	ixortable - change block via xor with inverted random table
**
**	This function inverts 50% of the bits.  It is the inverse function
**	for xortable, if the table is inverted.  Used for decryption.
*/
STATIC void ixortable(register byteptr block, register byteptr table)
/*	block is a 256 byte block.
	table contains random permutation of 256 bytes.
*/
{	register byte i;
	i = 0;		/* byte loop index i = 0,255,254,...2,1 */
	do	block[table[i]] ^= i;	/* inverted table xor */
	while (--i);	/* loop 256 times */
}	/* ixortable */


/*
**	rake - rake forwards and backwards with xor and add
**
**	This is not a keyed operation.  It is only useful for increasing
**	the intersymbol dependencies between the plaintext and the ciphertext,
**	not the key and the ciphertext.  Its inverse is function unrake.
*/
STATIC void rake(register byteptr block)
{	register byte i;
	register byteptr block1;
	block1 = block++;
	/* now block1 = 0, block = 1, relatively speaking */
	i = 255;	/* loop 255 times */
	/* first do forward raking with cumulative xor */
	do	/*  from  *1++ ^= *0++;  thru  *255++ ^= *254++; */
		*block++ ^= *block1++;
	while (--i);
	/* now block1 = 255, block = 256 */
	i = 255;	/* loop 255 times */
	/* now do backward raking with cumulative add */
	do	/*  from  *(--255) += *(--256);  thru  *(--1) += *(--2); */
		*(--block1) += *(--block);
	while (--i);
	/* now block1 = 0, block = 1 */
}	/* rake */


/*
**	unrake - unrake forwards and backwards with subtract and xor
**
**	This is the inverse function of rake.  Used for decryption.
*/
STATIC void unrake(register byteptr block)
{	register byte i;
	register byteptr block1;
	block1 = block++;
	/* now block1 = 0, block = 1, relatively speaking */
	i = 255;	/* loop 255 times */
	/* first do forward unraking with cumulative subtract */
	do	/*  from  *0++ -= *1++;  thru  *254++ -= *255++; */
		*block1++ -= *block++;
	while (--i);
	/* now block1 = 255, block = 256 */
	i = 255;	/* loop 255 times */
	/* now do backward unraking with cumulative xor */
	do	/*  from  *(--256) ^= *(--255);  thru  *(--2) ^= *(--1); */
		*(--block) ^= *(--block1);
	while (--i);
	/* now block1 = 0, block = 1 */
}	/* unrake */


/*
**	copy256(dst,src) - copy 256-byte buffer src to dst
*/
void copy256(register byteptr dst, register byteptr src)
{	register bytecounter size;
	size = 256;	/* loop 256 times */
	do *dst++ = *src++; while (--size);
} /* copy256 */


#define f(i,j) (((i)+(j)) & 7)	/* used for circular addressing mod 8 */
#define tl(i,j) tlist[f(i,j)]	/* assumes 8 tables */


/*
**	bassomatic - encipher 1 block with BassOmatic enciphering algorithm
**
**	Assumes initkey has already been called.
**	References context variables tlist, nrounds, shred8ways,
**	bitmasks, uncryp, rerand, and part.
*/
void bassomatic(byteptr in, byteptr out)
/*	in and out are input, output blocks, 256 bytes each. */
{	char i;		/* signed char */
	byteptr tmp;

	if (rerand)	/* dynamic replenishment of tables? */
		bldtbls(FALSE,uncryp);

	tmp = (byteptr) gblock(part);	/* get memory block */
	copy256(out,in);	/* copy in to out */

	if (uncryp)
	{ 	/* do decryption */
		for (i=nrounds-1; i>=0; i--)	/* repeat a few rounds */
		{	multilookup(out,tmp,f(i,2));
			unrake(tmp);		/* not effective if last step */
			if (shred8ways)		/* use 8-way bit shredding */
				shred1bit(tmp,out);
			else			/* use faster 2-way bit shredding */
				shred4bit(tmp,out,tl(i,1),tl(i,5),
					bitmasks[f(i,3)]);
			ixortable(out,tl(i,0));	/* inverts 50% of bits */
		} /* for loop */
	}	/* if decryption */
	else	/* do encryption */
	{	for (i=0; i<nrounds; i++)	/* repeat a few rounds */
		{	xortable(out,tl(i,0));	/* inverts 50% of bits */
			if (shred8ways)		/* use 8-way bit shredding */
				shred1bit(out,tmp);
			else			/* use faster 2-way bit shredding */
				shred4bit(out,tmp,tl(i,1),tl(i,5),
					bitmasks[f(i,3)]);
			rake(tmp);		/* not effective if last step */
			multilookup(tmp,out,f(i,2));
		} /* for loop */
	}	/* else encryption */
	rblock(part,tmp);	/* release block */
}	/* bassomatic */


/*
**	xorbuf - change buffer via xor with random mask block
**	Used for Cipher Feedback (CFB) or Cipher Block Chaining
**	(CBC) modes of encryption.
**	Can be applied for any block encryption algorithm,
**	such as the DES or the BassOmatic.
*/
STATIC void xorbuf(register byteptr buf, register byteptr mask, register int count)
/*	count must be > 0 */
{	do
		*buf++ ^= *mask++;
	while (--count);
}	/* xorbuf */


/*
**	cfbshift - shift bytes into IV for CFB input
**	Used only for Cipher Feedback (CFB) mode of encryption.
**	Can be applied for any block encryption algorithm,
**	such as the DES or the BassOmatic.
*/
STATIC void cfbshift(register byteptr iv, register byteptr buf, 
		register int count, int blocksize)
/* 	iv is the initialization vector.
	buf is the buffer pointer.
	count is the number of bytes to shift in...must be > 0.
	blocksize is 8 for DES, 256 for BassOmatic.
*/
{	int retained;
	retained = blocksize-count;	/* number bytes in iv to retain */
	/* left-shift retained bytes of IV over by count bytes to make room */
	while (retained--)
	{	*iv = *(iv+count);
		iv++;
	}
	/* now copy count bytes from buf to shifted tail of IV */
	do	*iv++ = *buf++;
	while (--count);
}	/* cfbshift */


#define BLOCKSIZE 256	/* encryption block size for CFB mode. */

/*
**	initcfb - Initializes the BassOmatic key schedule tables via key,
**	and initializes the Cipher Feedback mode IV.
**	References context variables cfbuncryp and iv.
*/
int initcfb(byteptr iv0, byteptr key, short keylen, boolean decryp)
/* 	iv0 is copied to global iv, buffer will be destroyed by basscfb.
	key is pointer to key buffer, up to 256 bytes long.
	keylen is length of key buffer.
	decryp is TRUE if decrypting, FALSE if encrypting.
*/
{	iv = iv0;	/* iv is not allocated from memory manager */
	cfbuncryp = decryp;
	return (initkey(key,keylen,FALSE));
} /* initcfb */


/*
**	basscfb - encipher 1 block with BassOmatic enciphering algorithm,
**		using Cipher Feedback (CFB) mode.
**
**	Assumes initcfb has already been called.
**	References context variables cfbuncryp and iv.
*/
void basscfb(byteptr buf, int count)
/*	buf is input, output buffer, may be more than 1 block.
	count is byte count of buffer.  May be > BLOCKSIZE.
*/
{	int chunksize;	/* smaller of count, BLOCKSIZE */
	byte temp[BLOCKSIZE];

	while ((chunksize = min(count,BLOCKSIZE)) > 0)
	{	bassomatic(iv,temp); /* encrypt iv. */

		if (cfbuncryp)	/* buf is ciphertext */
			/* shift in ciphertext to IV... */
			cfbshift(iv,buf,chunksize,BLOCKSIZE);

		/* convert buf via xor */
		xorbuf(buf,temp,chunksize); /* buf now has enciphered output */

		if (!cfbuncryp)	/* buf was plaintext, is now ciphertext */
			/* shift in ciphertext to IV... */
			cfbshift(iv,buf,chunksize,BLOCKSIZE);

		count -= chunksize;
		buf += chunksize;
	}
} /* basscfb */

