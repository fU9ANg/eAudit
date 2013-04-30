
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h> 

#include "capture_pub.h"
#include "capture_debug.h"

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

    (void)fprintf(stderr, "[DEBUG]%s:", "Capture");
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

    (void)fprintf(stderr, "[Info]%s: ", "Capture");
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

    (void)fprintf(stderr, "[Info]%s: ", "Capture");
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

	(void)fprintf(stderr, "%s: ", "Capture");
	
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

	(void)fprintf(stderr, "[WARNING]%s:", "Capture");
	
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
void PRINT_PAR(const char *format,...)
{
    char buf[MAX_PT_BUF_SIZE+1];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, MAX_PT_BUF_SIZE, format, args);
    va_end(args);
    fprintf(stderr, "%s", buf);
}
