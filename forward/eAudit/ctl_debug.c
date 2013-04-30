
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h> 
#include <sys/types.h>

#include "ctl_pub.h"
#include "ctl_debug.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void DEBUG(const char *fmt, ...)
{
#ifdef _DEBUG
    va_list ap;

    (void)fprintf(stderr, "[DEBUG]%s:", "eAudit ctl");
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {	
        fmt += strlen(fmt);
	 if (fmt[-1] != '\n')
	    (void)fputc('\n', stderr);
    }
#endif

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
void info(const char *fmt, ...)
{
#ifdef _INFO
    va_list ap;

    (void)fprintf(stderr, "%s: ", "eAudit ctl");
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {	
        fmt += strlen(fmt);
	 if (fmt[-1] != '\n')
	    (void)fputc('\n', stderr);
    }
#endif

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
void INFO(const char *fmt,...)
{
#ifdef _INFO
    va_list ap;

    (void)fprintf(stderr, "%s: ", "eAudit ctl");
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {	
        fmt += strlen(fmt);
	 if (fmt[-1] != '\n')
	    (void)fputc('\n', stderr);
    }
#endif

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
void error(const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: ", "eAudit ctl");
	
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void warning(const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "[WARNING]%s:", "eAudit ctl");
	
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}
