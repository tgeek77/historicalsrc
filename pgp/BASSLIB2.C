/*	basslib2.c - Bassomatic encryption password routines.
	(c) 1989 Philip Zimmermann.  All rights reserved.
	Implemented in Microsoft C.
	Routines for getting a Bassomatic-specific pass phrase from the 
	user's console.
*/

#include	<stdio.h>	/* for fprintf() */
#include	<ctype.h>	/* for isdigit(), toupper(), etc. */
#include	<string.h>	/* for strlen() */

#include	"random.h"	/* for getstring() */
#include	"basslib.h"
#include	"basslib2.h"


#define hexdigit(c) (isdigit((c))) ? ((c)-'0') : \
	( isxdigit((c)) ? (toupper((c))-'A'+10) : 0 )

static unsigned int gethex(char *p)
	/* Evaluate hex digit string */
{	unsigned int n;
	n = 0;
	while (isxdigit(*p)) {
		n = (n << 4) | ((int) hexdigit(*p));
		p++;
	}
	return (n);
} /* gethex */


/*
**	getpassword - get Bassomatic pass phrase from user.
	Parameters:
		returns char *keystring
		byte noecho:  
			0=ask once, echo. 
			1=ask once, no echo. 
			2=ask twice, no echo.
		int defaultc:  default key control byte, or -1 to prompt
	returns length of resulting keystring
*/
int getpassword(char *keystring, byte noecho, int defaultc)
{	char keystr2[256];
	char c;
	if (defaultc == -1) {
		fprintf(stderr,"\nEnter the Bassomatic key control byte in hex: ");
		fprintf(stderr,"\n(default = 12 hex): ");
		getstring(keystr2,48,TRUE);
		c = (strlen(keystr2)==0) ? 0x12 : gethex(keystr2);
	}
	else	c = defaultc;

	*keystring++ = c;

	while (TRUE) {
		fprintf(stderr,"\nEnter pass phrase: ");
		if (!noecho) fputc('\n',stderr);
		getstring(keystring,MAXKEYLEN-1,!noecho);
		if (noecho<2)	/* no need to ask again if user can see it */
			break;
		fprintf(stderr,"\nEnter same pass phrase again: ");
		if (!noecho) fputc('\n',stderr);
		getstring(keystr2,MAXKEYLEN-1,!noecho);
		if (strcmp(keystring,keystr2)==0)
			break;
		fprintf(stderr,"\n\aError: Pass phrases were different.  Try again.");
	}

	/* if (strlen(keystring)==0)
		strcpy(keystring," "); */ /* guarantee nonzero length */

	return(strlen(keystring));
}	/* getpassword */

