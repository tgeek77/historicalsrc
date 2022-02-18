/*	C include file for RSA library math routines

	Boulder Software Engineering
	3021 Eleventh Street
	Boulder, CO 80304
	(303) 444-4541

	(c) Copyright 1986 by Philip Zimmermann.  All rights reserved.
	The author assumes no liability for damages resulting from the use 
	of this software, even if the damage results from defects in this 
	software.  No warranty is expressed or implied.  

	These routines implement all of the multiprecision arithmetic necessary
	for RSA public key cryptography.

	Although originally developed in Microsoft C for the IBM PC, this code 
	contains few machine dependancies.  It assumes 2's complement 
	arithmetic.  It can be adapted to 8-bit, 16-bit, or 32-bit machines, 
	lowbyte-highbyte order or highbyte-lowbyte order.  This version
	has been converted to ANSI C.
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


/* #define PORTABLE	*/ /* determines if we use C primitives */
/* #define STEWART */ /* determines if we use Stewart's modmult */
/* #define ASM_MODMULT */ /* determines if we use assembly modmult */
/* #define UNIT8	*/ /* use 8-bit units */
/* #define UNIT16	*/ /* use 16-bit units */
/* #define UNIT32	*/ /* use 32-bit units */
/* #define HIGHFIRST	*/ /* determines if Motorola or Intel internal format */


#ifndef STEWART	/* if not Stewart's modmult algorithm */
#ifndef ASM_MODMULT	/* if not assembly modmult algorithm */
#ifndef PEASANT /* if not Russian peasant modulo multiply algorithm */
#define MERRITT	/* default: use Merritt's modmult algorithm */
#endif
#endif
#endif

#ifndef UNIT32
#ifndef UNIT8
#define UNIT16			/* default--use 16-bit units */
#endif
#endif

/***	CAUTION:  If your machine has an unusual word size that is not a
	power of 2 (8, 16, 32, or 64) bits wide, then the macros here that 
	use the symbol "LOG_UNITSIZE" must be changed.
***/

#ifdef UNIT8
typedef unsigned char unit;
typedef signed char signedunit;
#define UNITSIZE 8 /* number of bits in a unit */
#define uppermostbit ((unit) 0x80)
#define BYTES_PER_UNIT 1 /* number of bytes in a unit */
#define units2bits(n) ((n) << 3) /* fast multiply by UNITSIZE */
#define units2bytes(n) (n)
#define bits2units(n) (((n)+7) >> 3)
#define bytes2units(n) (n)
#endif

#ifdef UNIT16
typedef word16 unit;
typedef short signedunit;
#define UNITSIZE 16 /* number of bits in a unit */
#define uppermostbit ((unit) 0x8000)
#define BYTES_PER_UNIT 2 /* number of bytes in a unit */
#define units2bits(n) ((n) << 4) /* fast multiply by UNITSIZE */
#define units2bytes(n) ((n) << 1)
#define bits2units(n) (((n)+15) >> 4)
#define bytes2units(n) (((n)+1) >> 1)
#endif

#ifdef UNIT32
typedef word32 unit;
typedef long signedunit;
#define UNITSIZE 32 /* number of bits in a unit */
#define uppermostbit ((unit) 0x80000000)
#define BYTES_PER_UNIT 4 /* number of bytes in a unit */
#define units2bits(n) ((n) << 5) /* fast multiply by UNITSIZE */
#define units2bytes(n) ((n) << 2)
#define bits2units(n) (((n)+31) >> 5)
#define bytes2units(n) (((n)+3) >> 2)
#undef PORTABLE			/* can't use our C versions if 32 bits. */
#endif

#define power_of_2(b) ((unit) 1 << (b)) /* computes power-of-2 bit masks */
#define bits2bytes(n) (((n)+7) >> 3)
/*	Some C compilers (like the ADSP2101) will not always collapse constant 
	expressions at compile time if the expressions contain shift operators. */
/* #define uppermostbit power_of_2(UNITSIZE-1) */
/* #define UNITSIZE units2bits(1) */ /* number of bits in a unit */
/* #define bytes2units(n) bits2units((n)<<3) */
/* #define BYTES_PER_UNIT (UNITSIZE >> 3) */
/* LOG_UNITSIZE is the log base 2 of UNITSIZE, ie: 4 for 16-bit units */
/* #define units2bits(n) ((n) << LOG_UNITSIZE) */ /* fast multiply by UNITSIZE */
/* #define units2bytes(n) ((n) << (LOG_UNITSIZE-3)) */
/* #define bits2units(n) (((n)+(UNITSIZE-1)) >> LOG_UNITSIZE) */
/* #define bytes2units(n) (((n)+(BYTES_PER_UNIT-1)) >> (LOG_UNITSIZE-3)) */

typedef unit *unitptr;


/*--------------------- Byte ordering stuff -------------------*/
#ifdef HIGHFIRST

/* these definitions assume MSB comes first */
#define pre_higherunit(r)	(--(r))
#define pre_lowerunit(r)	(++(r))
#define post_higherunit(r)	((r)--)
#define post_lowerunit(r)	((r)++)
#define bit_index(n)		(global_precision-bits2units((n)+1))
#define lsbptr(r,prec)		((r)+(prec)-1)
#define make_lsbptr(r,prec)	(r) = lsbptr(r,prec)  
#define unmake_lsbptr(r,prec) (r) = ((r)-(prec)+1) 
#define msbptr(r,prec)		(r)
#define make_msbptr(r,prec)	/* (r) = msbptr(r,prec) */

#define rescale(r,currentp,newp) r -= ((newp) - (currentp))
#define normalize(r,prec) \
  { prec = significance(r); r += (global_precision-(prec)); }

#else	/* LOWFIRST byte order */

/* these definitions assume LSB comes first */
#define pre_higherunit(r)	(++(r))
#define pre_lowerunit(r)	(--(r))
#define post_higherunit(r)	((r)++)
#define post_lowerunit(r)	((r)--)
#define bit_index(n)		(bits2units((n)+1)-1)
#define lsbptr(r,prec)		(r)
#define make_lsbptr(r,prec)	/* (r) = lsbptr(r,prec) */  
#define unmake_lsbptr(r,prec) /* (r) = (r) */  
#define msbptr(r,prec)		((r)+(prec)-1)
#define make_msbptr(r,prec)	(r) = msbptr(r,prec)

#define rescale(r,currentp,newp) /* nil statement */
#define normalize(r,prec) prec = significance(r) 

#endif	/* LOWFIRST byte order */
/*------------------ End byte ordering stuff -------------------*/

/*	Note that the address calculations require that lsbptr, msbptr, 
	make_lsbptr, make_msbptr, mp_tstbit, mp_setbit, mp_clrbit, 
	and bitptr all have unitptr arguments, not byteptr arguments.  */
#define bitptr(r,n) &((r)[bit_index(n)])
#define mp_tstbit(r,n) (*bitptr(r,n) &   power_of_2((n) & (UNITSIZE-1)))
#define mp_setbit(r,n) (*bitptr(r,n) |=  power_of_2((n) & (UNITSIZE-1)))
#define mp_clrbit(r,n) (*bitptr(r,n) &= ~power_of_2((n) & (UNITSIZE-1)))
#define msunit(r) (*msbptr(r,global_precision))
#define lsunit(r) (*lsbptr(r,global_precision))
/* #define mp_tstminus(r) ((msunit(r) & uppermostbit)!=0) */
#define mp_tstminus(r) ((signedunit) msunit(r) < 0)

/*	MAX_BIT_PRECISION is upper limit that assembly primitives can handle.
	It must be less than 32704 bits, or 4088 bytes.  It should be an
	integer multiple of UNITSIZE*2.
*/
#define MAX_BIT_PRECISION 1024 /* limit for current 8086 primitives */
/* #define MAX_BIT_PRECISION 544 /* 544 is limit for ADSP2101 primitives */
#define MAX_BYTE_PRECISION (MAX_BIT_PRECISION/8)
#define MAX_UNIT_PRECISION (MAX_BIT_PRECISION/UNITSIZE)


/*************** multiprecision library primitives ****************/
#ifdef PORTABLE	/* using slow portable C primitives */

#define set_precision(prec) (global_precision = (prec))

#else	/* not PORTABLE - not using portable C primitives */
/*
	The following primitives should be coded in assembly.
	Functions P_ADDC, P_SUBB, and P_ROTL return a carry flag as their
	functional return, and the result of the operation is placed in r1.
	These assembly primitives are externally defined, unless PORTABLE 
	is defined.
*/

void P_SETP(short nbits);
	/* sets working precision to specified number of bits. */

boolean P_ADDC(unitptr r1, unitptr r2, boolean carry);
	/* multiprecision add with carry r2 to r1, result in r1 */

boolean P_SUBB(unitptr r1, unitptr r2, boolean borrow);
	/* multiprecision subtract with borrow, r2 from r1, result in r1 */

boolean P_ROTL(unitptr r1, boolean carry);
	/* multiprecision rotate left 1 bit with carry, result in r1. */

/* Define C primitive names as the equivalent calls to assembly primitives. */
#define set_precision(prec)	P_SETP(units2bits(global_precision=(prec)))
#define mp_addc		P_ADDC
#define mp_subb		P_SUBB
#define mp_rotate_left	 P_ROTL

#endif	/* not PORTABLE */
/************** end of primitives that should be in assembly *************/

#ifdef ASM_MODMULT	/* use assembly primitive modmult */

/*	The following modmult-related primitives can be coded in assembly.
	These assembly primitives are externally defined, 
	if ASM_MODMULT is defined.
*/

/* Define C names for assembly modmult primitives. */
#define stage_modulus P_STAGEMOD
#define mp_modmult P_MMULT
#define modmult_burn P_MMBURN

#endif	/* ASM_MODMULT */

#ifdef PEASANT

/* Define C names for Russian peasant modmult primitives. */
#define stage_modulus stage_peasant_modulus
#define mp_modmult peasant_modmult
#define modmult_burn peasant_burn

#endif	/* PEASANT */

#ifdef MERRITT
/* Define C names for Merritt's modmult primitives. */
#define stage_modulus stage_merritt_modulus
#define mp_modmult merritt_modmult
#define modmult_burn merritt_burn

#endif	/* MERRITT */

#ifdef STEWART
/* Define C names for Stewart's modmult primitives. */
#define stage_modulus stage_stewart_modulus
#define mp_modmult P_MMULT
#define modmult_burn stewart_burn

#endif	/* STEWART */


#define mp_shift_left(r1) mp_rotate_left(r1,(boolean)0)
	/* multiprecision shift left 1 bit */

#define mp_shift_right(r1) mp_rotate_right(r1,(boolean)0)
	/* multiprecision shift right 1 bit */

#define mp_add(r1,r2) mp_addc(r1,r2,(boolean)0)
	/* multiprecision add with no carry */

#define mp_sub(r1,r2) mp_subb(r1,r2,(boolean)0)
	/* multiprecision subtract with no borrow */

#define mp_abs(r) (mp_tstminus(r) ? (mp_neg(r),TRUE) : FALSE)

#define msub(r,m) if (mp_compare(r,m) >= 0) mp_sub(r,m)
	/* Prevents r from getting bigger than modulus m */

#define mp_burn(r) mp_init(r,0)	/* for burning the evidence */

#define testeq(r,i)	\
	( (lsunit(r)==(i)) && (significance(r)<=1) )

#define testne(r,i)	\
	( (lsunit(r)!=(i)) || (significance(r)>1) )

#define mp_square(r1,r2) mp_mult(r1,r2,r2)
	/* Square r2, returning product in r1 */

#define mp_modsquare(r1,r2) mp_modmult(r1,r2,r2)
	/* Square r2, returning modulo'ed product in r1 */

#define countbytes(r) ((countbits(r)+7)>>3)

/*	SLOP_BITS is how many "carry bits" to allow for intermediate 
	calculation results to exceed the size of the modulus.
	It is used by modexp to give some overflow elbow room for
	modmult to use to perform modulo operations with the modulus. 
	The number of slop bits required is determined by the modmult 
	algorithm.  The Russian peasant modmult algorithm only requires 
	1 slop bit, for example.  Note that if ASM_MODMULT is
	defined, SLOP_BITS may be meaningless or may be defined in a
	non-constant manner.
*/
#ifdef MERRITT	/* use Merritt's modmult algorithm */
#define SLOP_BITS (UNITSIZE+1)
#define MERRITT_KEY	/* cause keygen to generate unnormalized keys */
#endif	/* MERRITT */
#ifdef PEASANT	/* use Russian peasant modmult algorithm */
#define SLOP_BITS 1
#endif /* PEASANT */
#ifdef ASM_MODMULT	/* use external assembly modmult algorithm */
/* SLOP_BITS is likely either 1, UNITSIZE+1, non-constant or meaningless. */
#define SLOP_BITS 0
#endif /* ASM_MODMULT */
#ifdef STEWART	/* use Stewart's modmult modmult algorithm */
#define SLOP_BITS 0
#define STEWART_KEY	/* cause keygen to generate normalized keys */
#endif /* STEWART */


#ifndef RSALIB	/* not compiling RSALIB */
/* global_precision is the unit precision last set by set_precision */
extern short global_precision;
#endif	/* not compiling RSALIB */


#ifndef RSALIB	/* not compiling RSALIB */
	/*	Bug in DSP2101 C compiler -- no function protypes 
		allowed when compiling those same functions. */

#ifdef PORTABLE	/* these slow C primitives should be recoded in assembly */

boolean mp_addc
	(register unitptr r1,register unitptr r2,register boolean carry);
	/* multiprecision add with carry r2 to r1, result in r1 */

boolean mp_subb
	(register unitptr r1,register unitptr r2,register boolean borrow);
	/* multiprecision subtract with borrow, r2 from r1, result in r1 */

boolean mp_rotate_left(register unitptr r1,register boolean carry);
	/* multiprecision rotate left 1 bit with carry, result in r1. */

#endif	/* PORTABLE */

boolean mp_rotate_right(register unitptr r1,register boolean carry);
	/* multiprecision rotate right 1 bit with carry, r1. */

short mp_compare(register unitptr r1,register unitptr r2);
	/* Compares registers *r1, *r2, and returns -1, 0, or 1 */	

boolean mp_inc(register unitptr r);
	/* Increment multiprecision integer r. */

boolean mp_dec(register unitptr r);
	/* Decrement multiprecision integer r. */

void mp_neg(register unitptr r);
	/* Compute 2's complement, the arithmetic negative, of r */

void mp_move(register unitptr dst,register unitptr src);

void mp_init(register unitptr r, word16 value);
	/* Init multiprecision register r with short value. */

short significance(register unitptr r);
	/* Returns number of significant units in r */

int mp_udiv(register unitptr remainder,register unitptr quotient,
	register unitptr dividend,register unitptr divisor);
	/* Unsigned divide, treats both operands as positive. */

int mp_div(register unitptr remainder,register unitptr quotient,
	register unitptr dividend,register unitptr divisor);
	/* Signed divide, either or both operands may be negative. */

word16 mp_shortdiv(register unitptr quotient,
	register unitptr dividend,register word16 divisor);
	/* Returns short remainder of unsigned divide. */

int mp_mod(register unitptr remainder,
	register unitptr dividend,register unitptr divisor);
	/* Unsigned divide, treats both operands as positive. */

word16 mp_shortmod(register unitptr dividend,register word16 divisor);
	/* Just returns short remainder of unsigned divide. */

int mp_mult(register unitptr prod,
	register unitptr multiplicand,register unitptr multiplier);
	/* Computes multiprecision prod = multiplicand * multiplier */

void stage_modulus(unitptr n);
	/* Must pass modulus to stage_modulus before calling modmult. */

int mp_modmult(register unitptr prod,
	unitptr multiplicand,register unitptr multiplier);
	/* Performs combined multiply/modulo operation, with global modulus */

int countbits(unitptr r);
	/* Returns number of significant bits in r. */

int mp_modexp(register unitptr expout,register unitptr expin,
	register unitptr exponent,register unitptr modulus);
	/* Combined exponentiation/modulo algorithm. */

int rsa_decrypt(unitptr M, unitptr C,
	unitptr d, unitptr p, unitptr q, unitptr u);
	/* Uses Chinese Remainder Theorem shortcut for RSA decryption. */

int mp_sqrt(unitptr quotient,unitptr dividend); 
	/* Quotient is returned as the square root of dividend. */

#endif	/* not compiling RSALIB */

/****************** end of RSA library ****************************/

