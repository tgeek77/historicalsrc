/*--------------------------------------------------------------------------*/
/*  lzh.c - file compression subroutines for lzss + Huffman encoding        */
/*                                                                          */
/*  Source code history:                                                    */
/*                                                                          */
/*      The original lzhuf.c source was written by Haruyasu Yoshizaki on    */
/*      11/20/1988 with some minor changes 4/6/1989.  Comments were         */
/*      translated by Haruhiko Okumura on 4/7/1989.                         */
/*                                                                          */
/*      The original lzss compression was written by Haruhiko Okumura,      */
/*      12-2-404 Green Heights, 580 Nagasawa, Yokosuka 239, Japan.  The     */
/*      Adaptive Huffman algorithm was added by Yoshizaki to increase       */
/*      speed and compression and developed it into the LHarc archiver.     */
/*                                                                          */
/*      Modifications were made by Allan Hoeltje P.O. Box 18045 Boulder,    */
/*      Colorado, USA 80308-8045, during the month of June 1989.  These     */
/*      modifications include: More comments; better file error handling;   */
/*      run-length encoding input and output to increase the compression    */
/*      ratio.  Note: the run length encoding gives you about 2 to 5 per    */
/*      cent better compression but more importantly it speeds up the       */
/*      compression process on text files by about 60 per cent.             */
/*                                                                          */
/*      Additional modifications made on February 17, 1991 to make the      */
/*      routines more usable as subroutines for a parent application.       */
/*      The two routines, lzhEncode and lzhDecode are the main entry        */
/*      points.  Everything else is static.                                 */
/*                                                                          */
/*      It is my understanding that the lzHuff algorithm and source code    */
/*      is in the public domain and it's use is free and unrestricted.      */
/*--------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rsalib.h"
#include "rsaio.h"

/*
**	Convert to or from external byte order.
**	Note that hilo_swap does nothing if this is a LSB-first CPU.
*/

#define convert2(x,lx)	hilo_swap( (byteptr)&(x), (lx) )
#define convert(x)		convert2( (x), sizeof(x) )


#define EXIT_FAILURE   1
#define EXIT_SUCCESS   0
typedef unsigned char uchar;

static FILE    *inFile;                        /*  clear text input    */
static FILE    *outFile;                       /*  compressed output   */

static unsigned long int   codesize    = 0;
static unsigned long int   inCount     = 0;
static unsigned long int   outCount    = 0;

void Error( char *message )
    {
    printf( "\n%s\n", message );
    exit( EXIT_FAILURE );
    }

/*--------------------------------------------------------------------------*/
/*  Run length encoded getc and putc routines.                              */
/*--------------------------------------------------------------------------*/

/*		getCHR
		This does a simple getc and count.
*/
static int getCHR( FILE *f )
    {
    int c;
    if ((c = getc( f )) != EOF)
        inCount++;
    return( c );
    }


/*		putCHR
		This does a simple putc and count with a write error check.
*/
void putCHR( int c, FILE *f )
    {
    if (putc( c, f ) == EOF)
        {
        Error( "lzh putCHR: can't write output file!" );
        }
    outCount++;
    }


#define NOHIST   0                      /* don't consider previous input    */
#define INREP    1                      /* sending a repeated value         */
#define SENTCHAR 1                      /* lastchar set, no lookahead yet   */
#define SENDNEWC 2                      /* run over, send new char next     */
#define SENDCNT  3                      /* newchar set, send count next     */
#define DLE      0x90                   /* repeat sequence marker           */

static unsigned char state = NOHIST;    /* current packing state            */

/*--------------------------------------------------------------------------*/
/*  getRLC                                                                  */
/*      Non-repeat compression - text is read from file "f" and passed      */
/*      through normally except that a run of more than two characters is   */
/*      encoded as: <char> <DLE> <count>.  Special case: a count of zero    */
/*      indicates that the DLE is really a DLE, not a repeat marker.        */
/*--------------------------------------------------------------------------*/

static int
getRLC( FILE *f )
    {
    static int lastc;                   /* value returned on last call   */
    static int repcnt;                  /* repetition counter    */
    static int c;                       /* latest value seen     */
    static char *badstate = "lzh getRLC: Bad packing state!";

    switch (state)                      /* depends on our state  */
        {
        case NOHIST:                    /* no relevant history   */
            state = SENTCHAR;
            return (lastc = getCHR(f));   /* remember the value next time */
            break;
        case SENTCHAR:                  /* char was sent. look ahead    */
            switch (lastc)              /* action depends on char       */
                {
                case DLE:                 /* if we sent a real DLE */
                    state = NOHIST;       /* then start over again */
                    return (0);           /* but note that the DLE was real */
                    break;
                case EOF:                 /* EOF is always a special case */
                    return (EOF);
                    break;
                default:                  /* else test for a repeat */
                    for (repcnt = 1 ;
                        ((c = getCHR(f)) == lastc) && (repcnt < 255) ;
                        repcnt++);           /* find end of run */

                    switch(repcnt)           /* action depends on run size */
                        {
                        case 1:                 /* not a repeat */
                            return (lastc = c); /* but remember value next time */
                            break;
                        case 2:                 /* a repeat, but too short */
                            state = SENDNEWC;   /* send the second one next time */
                            return (lastc);
                            break;
                        default:                /* a run - compress it */
                            state = SENDCNT;    /* send repeat count next time */
                            return (DLE);       /* send repeat marker this time */
                            break;
                        }
                }
            case SENDNEWC:                   /* send second char of short run */
                state = SENTCHAR;
                return (lastc = c);
                break;
            case SENDCNT:                    /* sent DLE, now send count */
                state = SENDNEWC;
                return (repcnt);
                break;
            default:
                {
                Error( badstate );
                }
        }
    }


/*--------------------------------------------------------------------------*/
/*  putRLC                                                                  */
/*      This routine is used to decode non-repeat compression bytes and     */
/*      write them to file "t".  Bytes are passed one at a time in coded    */
/*      format, and are written out uncoded.  The data is stored normally,  */
/*      except that runs of more than two characters are represented as:    */
/*                                                                          */
/*                          <char> <DLE> <count>                            */
/*      with a special case that a count of zero indicates a DLE as data,   */
/*      not as a repeat marker.                                             */
/*--------------------------------------------------------------------------*/

static int
putRLC( int c, FILE *t )
    {
    static int lastc;                   /* last character seen */
    static char *badstate = "lzh putRLC: Bad unpacking state!";

    switch (state)                      /* action depends on our state  */
        {
        case NOHIST:                        /* no previous history      */
            if (c == DLE)                   /* if starting a series     */
                state = INREP;              /* then remember it next time */
            else
                putCHR( (lastc = c), t );     /* else nothing unusual     */
            break;
        case INREP:                         /* in a repeat              */
            if (c)                          /* if count is nonzero      */
                while(--c)                  /* then repeatedly ...      */
                    putCHR( lastc, t );       /* ... output the byte      */
            else
                putCHR( DLE, t );             /* else output DLE as data  */
            state = NOHIST;                 /* back to no history       */
            break;
        default:
            {
            Error( badstate );
            }
        }
    return(0);
    }


/*--------------------------------------------------------------------------*/
/*                             LZSS Compression                             */
/*--------------------------------------------------------------------------*/

#define buffSize    2048        /* size of ring buffer   */
#define lookSize    60          /* lookahead buffer size */
#define THRESHOLD   2           /* if matchLen is greater than Threshold    */
                                /* then code string into position & length  */
#define treeRoot    buffSize    /* index for root of binary search tree     */

    /*
        ring buffer with extra bytes to facilitate string comparison of
        longest match.  This is set by the InsertNode() procedure.
    */

static unsigned char   textBuf[ buffSize + lookSize - 1 ];
static int             matchPos, matchLen;
static int             lson[ buffSize + 1   ];
static int             rson[ buffSize + 257 ];
static int             dad [ buffSize + 1   ];


/*--------------------------------------------------------------------------*/
/*  InitTree                                                                */
/*      Initialize the LZSS trees.                                          */
/*--------------------------------------------------------------------------*/

static void InitTree( void )
    {
    register int  i;

    /*
       For i = 0 to buffSize, rson[i] and lson[i] will be the right and
       left children of node i.  These nodes need not be initialized.  Also,
       dad[i] is the parent of node i.  These are initialized to "treeRoot"
       which means 'not used.'

       For i = buffSize+1 to buffSize+256, rson[i] is the root of the tree
       for strings that begin with character i.  These are initialized
       to "treeRoot".  Note there are 256 trees.
    */

    for (i = buffSize + 1 ; i <= (buffSize + 256) ; i++)
        rson[i] = treeRoot;            /* root */
    for (i = 0 ; i < buffSize ; i++)
        dad[i] = treeRoot;             /* node */
    }


/*--------------------------------------------------------------------------*/
/*  InsertNode                                                              */
/*      Inserts string of length lookSize, textBuf[r..r+lookSize-1], into   */
/*  one of the trees (textBuf[r]'th tree) and returns the longest-match     */
/*  position and length via the global variables matchPos and matchLen.     */
/*  If matchLen = lookSize, then remove the old node in favor of the new    */
/*  one, because the old one will be deleted sooner.  Note r plays double   */
/*  role, as tree node and position in buffer.                              */
/*--------------------------------------------------------------------------*/

static void InsertNode(int r)
    {
    int             i, p, cmp;
    unsigned char   *key;
    unsigned        c;

    cmp = 1;
    key = &textBuf[r];
    p = buffSize + 1 + key[0];
    rson[r] = lson[r] = treeRoot;
    matchLen = 0;
    for ( ; ; )
        {
        if (cmp >= 0)
            {
            if (rson[p] != treeRoot)
                p = rson[p];
            else
                {
                rson[p] = r;
                dad [r] = p;
                return;
                }
            }
        else
            {
            if (lson[p] != treeRoot)
                p = lson[p];
            else
                {
                lson[p] = r;
                dad [r] = p;
                return;
                }
            }
        for (i = 1; i < lookSize; i++)
            if ((cmp = key[i] - textBuf[p + i]) != 0)
                break;
        if (i > THRESHOLD)
            {
            if (i > matchLen)
                {
                matchPos = ((r - p) & (buffSize - 1)) - 1;
                if ((matchLen = i) >= lookSize)
                    break;
                }
            if (i == matchLen)
                {
                if ((c = ((r - p) & (buffSize - 1)) - 1) < matchPos)
                    {
                    matchPos = c;
                    }
                }
            }
        }
    dad[r]  = dad[p];
    lson[r] = lson[p];
    rson[r] = rson[p];
    dad[lson[p]] = r;
    dad[rson[p]] = r;
    if (rson[dad[p]] == p)
        rson[dad[p]] = r;
    else
        lson[dad[p]] = r;
    dad[p] = treeRoot;  /* remove p */
    }


/*--------------------------------------------------------------------------*/
/*  DeleteNode                                                              */
/*      Delete node p from the tree.                                        */
/*--------------------------------------------------------------------------*/

static void DeleteNode( register int p )
    {
    register int  q;

    if (dad[p] == treeRoot)
        return;            /* not registered */
    if (rson[p] == treeRoot)
        q = lson[p];
    else
    if (lson[p] == treeRoot)
        q = rson[p];
    else
        {
        q = lson[p];
        if (rson[q] != treeRoot)
            {
            do  {
                q = rson[q];
                }
            while (rson[q] != treeRoot);

            rson[dad[q]] = lson[q];
            dad[lson[q]] = dad[q];
            lson[q] = lson[p];
            dad[lson[p]] = q;
            }
        rson[q] = rson[p];
        dad[rson[p]] = q;
        }
    dad[q] = dad[p];

    if (rson[dad[p]] == p)
        rson[dad[p]] = q;
    else
        lson[dad[p]] = q;
    dad[p] = treeRoot;
    }

/*--------------------------------------------------------------------------*/
/*                              Huffman Coding                              */
/*--------------------------------------------------------------------------*/

                    /* kinds of characters (character code = 0..N_CHAR-1)   */
#define N_CHAR      (256 - THRESHOLD + lookSize)
#define tableSize   (N_CHAR * 2 - 1)    /* size of table        */
#define rootSize    (tableSize - 1)     /* position of root     */
#define MAX_FREQ    0x8000              /* update the tree when the root    */
                                        /* frequency comes to this value.   */

/*--------------------------------------------------------------------------*/
/*  Tables for encoding the upper 6 bits of position                        */
/*--------------------------------------------------------------------------*/

static uchar p_len[64] =
    {
    0x03, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08
    };

static uchar p_code[64] =
    {
    0x00, 0x20, 0x30, 0x40, 0x50, 0x58, 0x60, 0x68,
    0x70, 0x78, 0x80, 0x88, 0x90, 0x94, 0x98, 0x9C,
    0xA0, 0xA4, 0xA8, 0xAC, 0xB0, 0xB4, 0xB8, 0xBC,
    0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE,
    0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
    0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    };

/*--------------------------------------------------------------------------*/
/*  Tables for decoding the upper 6 bits of position                        */
/*--------------------------------------------------------------------------*/

static uchar d_code[256] =
    {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0E, 0x0E, 0x0E, 0x0E, 0x0F, 0x0F, 0x0F, 0x0F,
    0x10, 0x10, 0x10, 0x10, 0x11, 0x11, 0x11, 0x11,
    0x12, 0x12, 0x12, 0x12, 0x13, 0x13, 0x13, 0x13,
    0x14, 0x14, 0x14, 0x14, 0x15, 0x15, 0x15, 0x15,
    0x16, 0x16, 0x16, 0x16, 0x17, 0x17, 0x17, 0x17,
    0x18, 0x18, 0x19, 0x19, 0x1A, 0x1A, 0x1B, 0x1B,
    0x1C, 0x1C, 0x1D, 0x1D, 0x1E, 0x1E, 0x1F, 0x1F,
    0x20, 0x20, 0x21, 0x21, 0x22, 0x22, 0x23, 0x23,
    0x24, 0x24, 0x25, 0x25, 0x26, 0x26, 0x27, 0x27,
    0x28, 0x28, 0x29, 0x29, 0x2A, 0x2A, 0x2B, 0x2B,
    0x2C, 0x2C, 0x2D, 0x2D, 0x2E, 0x2E, 0x2F, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    };

static uchar d_len[256] =
    {
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    };

static unsigned freq[tableSize + 1];    /* frequency table */

static int     prnt[ tableSize + N_CHAR ];
            /* pointers to parent nodes, except for the elements    */
            /* [tableSize..tableSize + N_CHAR - 1] which are used   */
            /* to get the positions of leaves corresponding to the  */
            /* codes.                                               */

static int     son[ tableSize ];   /* pointers to child nodes (son[], son[] + 1) */

static unsigned    getbuf = 0;
static uchar       getlen = 0;


/*--------------------------------------------------------------------------*/
/*  GetBit                                                                  */
/*      Get one bit.                                                        */
/*--------------------------------------------------------------------------*/

static int GetBit( void )
    {
    int i;

    while (getlen <= 8)
        {
        if ((i = getc( inFile )) < 0)
            i = 0;
        getbuf |= i << (8 - getlen);
        getlen += 8;
        }
    i = getbuf;
    getbuf <<= 1;
    getlen--;
    return (i < 0);
    }


/*--------------------------------------------------------------------------*/
/*  GetByte                                                                 */
/*      Get one byte.                                                       */
/*--------------------------------------------------------------------------*/

static int GetByte( void )
    {
    unsigned i;

    while (getlen <= 8)
        {
        if ((i = getc( inFile )) < 0)
            i = 0;
        getbuf |= i << (8 - getlen);
        getlen += 8;
        }
    i = getbuf;
    getbuf <<= 8;
    getlen -= 8;
    return i >> 8;
    }


/*--------------------------------------------------------------------------*/
/*  Putcode                                                                 */
/*      Write c bits of code.                                               */
/*--------------------------------------------------------------------------*/

static unsigned    putbuf = 0;
static uchar       putlen = 0;

static void Putcode(int l, unsigned c)
    {
	static char	*werr = "lzh Putcode: can't write output file!";

    putbuf |= (c >> putlen);
    if ((putlen += l) >= 8)
        {
        if (putc( putbuf >> 8, outFile ) == EOF)
            {
            Error( werr );
            }
        if ((putlen -= 8) >= 8)
            {
            if (putc( putbuf, outFile ) == EOF)
                {
                Error( werr );
                }
            codesize += 2;
            putlen   -= 8;
            putbuf    = c << (l - putlen);
            }
        else
            {
            putbuf <<= 8;
            codesize++;
            }
        }
    }


/*--------------------------------------------------------------------------*/
/*  StartHuff                                                               */
/*      initialize the Huffman trees.                                       */
/*--------------------------------------------------------------------------*/

static void StartHuff( void )
    {
    register int i, j;

    for (i = 0; i < N_CHAR; i++)
        {
        freq[i] = 1;
        son[i]  = i + tableSize;
        prnt[i + tableSize] = i;
        }
    i = 0;
    j = N_CHAR;

    while (j <= rootSize)
        {
        freq[j] = freq[i] + freq[i + 1];
        son[j]  = i;
        prnt[i] = prnt[i + 1] = j;
        i += 2;
        j++;
        }
    freq[tableSize] = 0xffff;
    prnt[rootSize] = 0;
    }


/*--------------------------------------------------------------------------*/
/*  reconst                                                                 */
/*      Reconstruction of tree.                                             */
/*--------------------------------------------------------------------------*/

static void reconst( void )
    {
    register int    i, j, k;
    unsigned int    f, l;

    /* Collect leaf nodes in the first half of the table and replace the    */
    /* freq by (freq + 1) / 2.                                              */

    j = 0;
    for (i = 0; i < tableSize; i++)
        {
        if (son[i] >= tableSize)
            {
            freq[j] = (freq[i] + 1) / 2;
            son[j]  = son[i];
            j++;
            }
        }

    /* begin constructing tree by connecting sons */

    for (i = 0, j = N_CHAR; j < tableSize; i += 2, j++)
        {
        k = i + 1;
        f = freq[j] = freq[i] + freq[k];

        for (k = j - 1; f < freq[k]; k--);

        k++;
        l = (j - k) * 2;
        memmove( &freq[k + 1], &freq[k], l );
        freq[k] = f;
        memmove( &son[k + 1], &son[k], l );
        son[k] = i;
        }

    /* connect prnt */

    for (i = 0; i < tableSize; i++)
        if ((k = son[i]) >= tableSize)
            prnt[k] = i;
        else
            prnt[k] = prnt[k + 1] = i;
    }


/*--------------------------------------------------------------------------*/
/*  update                                                                  */
/*      Increment frequency of given code by one, and update tree.          */
/*--------------------------------------------------------------------------*/

static void update(int c)
    {
    int i, j, k, l;

    if (freq[rootSize] == MAX_FREQ)
        reconst();

    c = prnt[c + tableSize];
    do  {
        k = ++freq[c];

        /* if the order is disturbed, exchange nodes */
        if (k > freq[l = c + 1])
            {
            while (k > freq[++l]);
            l--;
            freq[c] = freq[l];
            freq[l] = k;

            i = son[c];
            prnt[i] = l;
            if (i < tableSize)
                prnt[i + 1] = l;

            j = son[l];
            son[l] = i;

            prnt[j] = c;
            if (j < tableSize)
                prnt[j + 1] = c;
            son[c] = j;

            c = l;
            }
        }
    while ((c = prnt[c]) != 0);    /* repeat up to root */
    }


/*--------------------------------------------------------------------------*/
/*  EncodeChar                                                              */
/*--------------------------------------------------------------------------*/

static void EncodeChar(unsigned c)
    {
    unsigned i;
    int j, k;

    i = j = 0;
    k = prnt[c + tableSize];

    /* travel from leaf to root */
    do {
        i >>= 1;

        /* if node's address is odd-numbered, choose bigger brother node */
        if (k & 1) i += 0x8000;

        j++;
        }
    while ((k = prnt[k]) != rootSize);

    Putcode(j, i);
    update(c);
    }


/*--------------------------------------------------------------------------*/
/*  EncodePosition                                                          */
/*--------------------------------------------------------------------------*/

static void EncodePosition(unsigned c)
    {
    unsigned i;

    /* output upper 6 bits by table lookup */

    i = c >> 6;
    Putcode( p_len[i], (unsigned)p_code[i] << 8 );

    /* output lower 6 bits verbatim */
    Putcode( 6, (c & 0x3f) << 10 );
    }


/*--------------------------------------------------------------------------*/
/*  EncodeEnd                                                               */
/*--------------------------------------------------------------------------*/

static void EncodeEnd( void )
    {
	static char	*werr = "lzh EncodeEnd: can't write output file!";

    if (putlen)
        {
        if (putc(putbuf >> 8, outFile) == EOF)
            Error( werr );
        codesize++;
        }
    }


/*--------------------------------------------------------------------------*/
/*  DecodeChar                                                              */
/*--------------------------------------------------------------------------*/

static int DecodeChar( void )
    {
    register unsigned c;

    /* Travel from root to leaf choosing the smaller child node (son[]) if  */
    /* the read bit is 0, the bigger (son[]+1} if 1.                        */

    c = son[rootSize];
    while (c < tableSize)
        {
        c += GetBit();
        c  = son[c];
        }
    c -= tableSize;
    update(c);
    return c;
    }


/*--------------------------------------------------------------------------*/
/*  DecodePosition                                                          */
/*--------------------------------------------------------------------------*/

static int DecodePosition( void )
    {
    register unsigned i, j, c;

    /* recover upper 6 bits from table */
    i = GetByte();
    c = (unsigned)d_code[i] << 6;
    j = d_len[i];

    /* read lower 6 bits verbatim */
    j -= 2;
    while (j--)
        i = (i << 1) + GetBit();
    return (c | (i & 0x3f));
    }


/*		lzhEncode
		Compress the input file and write to the output file.
		Return the ratio of output to input size.
*/
int lzhEncode( FILE *in, FILE *out )
    {
    int  i, c, len, r, s, last_matchLen;
    unsigned long int   textsize, beginByte;
	static char *werr = "lzhEncode: can't write output file!";

	inFile  = in;			/*	set the global file pointers */
	outFile = out;

    /*	Skip to the end of file and get the byte length.  Write the length
    	as the first word in the compressed output file.
	*/
    beginByte = ftell( inFile );	/* just in case we were prepositioned */
    fseek( inFile, 0L, SEEK_END );
    textsize = ftell( inFile ) - beginByte;
    fseek( inFile, beginByte, SEEK_SET );	/* go back to the beginning of the file */

    if (textsize == 0)
        return( -1 );		/* empty files are easy - signal an error */

	convert( textsize );	/* convert to little endian if necessary */

    if (fwrite( &textsize, sizeof textsize, 1, outFile ) < 1)
        Error( werr );

    StartHuff();            /*  init the Huffman trees  */
    InitTree();             /*  init the LZSS trees     */
    inCount = 0;            /*  init the input character count  */
    s = 0;
    r = buffSize - lookSize;
    for (i = 0; i < r; i++)
        textBuf[i] = ' ';

    /*  fill the look ahead buffer  */

    for (len = 0; (len < lookSize) && ((c = getRLC( inFile )) != EOF); len++)
        textBuf[r + len] = c;
    for (i = 1; i <= lookSize; i++)
        InsertNode( r - i );
    InsertNode( r );
    do  {
        if (matchLen > len)
            matchLen = len;
        if (matchLen <= THRESHOLD)
            {
            matchLen = 1;
            EncodeChar( textBuf[r] );
            }
        else
            {
            EncodeChar( 255 - THRESHOLD + matchLen );
            EncodePosition( matchPos );
            }
        last_matchLen = matchLen;
        for (i = 0; (i < last_matchLen) && ((c = getRLC( inFile )) != EOF); i++)
            {
            DeleteNode( s );
            textBuf[s] = c;
            if (s < lookSize - 1)
                textBuf[s + buffSize] = c;
            s = (s + 1) & (buffSize - 1);
            r = (r + 1) & (buffSize - 1);
            InsertNode( r );
            }

        while (i++ < last_matchLen)
            {
            DeleteNode( s );
            s = (s + 1) & (buffSize - 1);
            r = (r + 1) & (buffSize - 1);
            if (--len)
                InsertNode( r );
            }
        }
    while (len > 0);

    EncodeEnd();

	return( (int)((codesize * 10) / inCount ));
    }


/*--------------------------------------------------------------------------*/
/*  lzhDecode                                                               */
/*--------------------------------------------------------------------------*/

void lzhDecode( FILE *in, FILE *out )
    {
    int  i, j, k, r, c;
    unsigned long int   textsize;
	static char *werr = "lzhDecode: can't write output file!";

	inFile  = in;	/* set the global file pointers */
	outFile = out;

	/* get the size of the input file in the first word */

    if (fread( &textsize, sizeof textsize, 1, inFile ) < 1)
        Error( "lzhDecode: Can't read the input file" );

	convert( textsize );	/* convert to little endian if necessary */
    if (textsize == 0)
        return;             /*  nothing to decode, empty file   */

    StartHuff();
    for (i = 0; i < (buffSize - lookSize); i++)
        textBuf[i] = ' ';
    r = buffSize - lookSize;

    outCount = 0;           /*  init the output character count */
    while (outCount < textsize )
        {
        c = DecodeChar();
        if (c < 256)
            {
            if (putRLC( c, outFile ) == EOF)
                Error( werr );

            textBuf[r++] = c;
            r &= (buffSize - 1);
            }
        else
            {
            i = (r - DecodePosition() - 1) & (buffSize - 1);
            j = c - 255 + THRESHOLD;
            for (k = 0; k < j; k++)
                {
                c = textBuf[(i + k) & (buffSize - 1)];
                if (putRLC( c, outFile ) == EOF)
                    Error( werr );
                textBuf[r++] = c;
                r &= (buffSize - 1);
                }
            }
        }
    }

/* ----	end of lzh.c */

