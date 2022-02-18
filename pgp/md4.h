/* 
** **************************************************************************
** md4.h -- Header file for implementation of MD4 Message Digest Algorithm **
** Updated: 2/13/90 by Ronald L. Rivest                                    **
** (C) 1990 RSA Data Security, Inc.                                        **
** Data type Word32Type added by Peter Pearson, 90.08.02.                  **
** **************************************************************************
*/

/*
License to copy and use this software is granted provided it is 
identified as the "RSA Data Security, Inc. MD4 Message Digest 
Algorithm" in all materials mentioning or referencing this software, 
function, or document.

License is also granted to make derivative works provided that such
works are identified as "derived from the RSA Data Security, Inc. MD4
Message Digest Algorithm" in all material mentioning or referencing
the derived work.

RSA Data Security, Inc. makes no representations concerning the
merchantability of this algorithm or software or their suitability
for any specific purpose.  It is provided "as is" without express or
implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
*/

typedef unsigned long Word32Type ;

/* MDstruct is the data structure for a message digest computation.
*/
typedef struct {
  Word32Type   buffer[4];    /* Holds 4-word result of MD computation */
  unsigned char count[8];    /* Number of bits processed so far */
  unsigned int done;         /* Nonzero means MD computation finished */
} MDstruct, *MDptr;

/* MDbegin(MD)
** Input: MD -- an MDptr
** Initialize the MDstruct prepatory to doing a message digest computation.
*/
extern void MDbegin(MDptr MDp) ;

/* MDupdate(MD,X,count)
** Input: MD -- an MDptr
**        X -- a pointer to an array of unsigned characters.
**        count -- the number of bits of X to use (an unsigned int).
** Updates MD using the first ``count'' bits of X.
** The array pointed to by X is not modified.
** If count is not a multiple of 8, MDupdate uses high bits of last byte.
** This is the basic input routine for a user.
** The routine terminates the MD computation when count < 512, so
** every MD computation should end with one call to MDupdate with a
** count less than 512.  Zero is OK for a count.
*/
extern void MDupdate(MDptr MDp, unsigned char *X, Word32Type count) ;


/* MDprint(MD)
** Input: MD -- an MDptr
** Prints message digest buffer MD as 32 hexadecimal digits.
** Order is from low-order byte of buffer[0] to high-order byte of buffer[3].
** Each byte is printed with high-order hexadecimal digit first.
*/
extern void MDprint(MDptr MDp) ;

/* 
** End of md4.h
*/

