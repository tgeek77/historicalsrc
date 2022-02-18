/*	keygen.h - C include file for RSA key generation routines

	(c) Copyright 1986 by Philip Zimmermann.  All rights reserved.
	The author assumes no liability for damages resulting from the use 
	of this software, even if the damage results from defects in this 
	software.  No warranty is expressed or implied.  

	NOTE:  This assumes previous inclusion of "rsalib.h"
*/

extern word16 primetable[]; /* table of small primes, zero-terminated.*/

boolean primetest(unitptr p);
	/* Returns TRUE iff p is a prime. */

int nextprime(unitptr p);
	/* Find next higher prime starting at p, returning result in p. */

void randombits(unitptr p,short nbits);
	/* Make a random unit array p with nbits of precision. */

int randomprime(unitptr p,short nbits);
	/* Makes a "random" prime p with nbits significant bits of precision. */

void gcd(unitptr result,unitptr a,unitptr n);
	/* Computes greatest common divisor via Euclid's algorithm. */

void inv(unitptr x,unitptr a,unitptr n);
	/* Euclid's algorithm extended to compute multiplicative inverse.
	   Computes x such that a*x mod n = 1, where 0<a<n */

void derivekeys(unitptr n,unitptr e,unitptr d,
	unitptr p,unitptr q,unitptr u,short ebits);
	/* Given primes p and q, derive key components n, e, d, and u. */

int keygen(unitptr n,unitptr e,unitptr d,
	unitptr p,unitptr q,unitptr u,short keybits,short ebits);
	/* Generate key components p, q, n, e, d, and u. */

