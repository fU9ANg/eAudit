/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <string.h>
#include <ctype.h>
#include "eAudit_string.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
size_t strlcpy(char *dst, const char *src, size_t siz)
{
	register char *d = dst;
	register const char *s = src;
	register size_t n = siz;

	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	if (n == 0) {
		if (siz != 0)
			*d = '\0';		
		while (*s++)
			;
	}

	return(s - src - 1);	
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void left_trim(char *src)
{
    register char *str = src;
    register char *s = src;
    
    while(*str != '\0')
    {
        if (0 == isspace(*str))
        	  break;     
        str++; 
    }
    
    if (str != s)
    	while((*s++ = *str++) != '\0');
    
    return;      
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void right_trim(char *src)
{
    unsigned long i = 0;
    unsigned len = 0;
    register char *str = src;
 
    len = strlen(str);
    i = len;

    while(i >= 0)
    {
        if (0 == isspace(str[i]))
        	  break;
        i--;
    }
   
    if (i < len)
    	str[i] = '\0';
    
    return;      
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void trim(char *src)
{
    char *s = src;
    
    left_trim(s);
    right_trim(s);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
char *quick_trim(char *src)
{
    register char *s = src;
    char *addr = NULL;
    
    while(*s != '\0')
    {
        if (0 == isspace(*s))
        	  break;       	  

        s++;
    }
    
    addr = s;
    right_trim(addr);

    return addr;
}
