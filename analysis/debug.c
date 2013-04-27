/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"


void DEBUG(const char *fmt, ...)
{
#ifdef _DEBUG
	va_list ap;
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if(*fmt) {	
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
#endif

	return;
}


void info(const char *fmt, ...)
{
#ifdef _INFO
	va_list ap;

	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if(*fmt){	
		fmt += strlen(fmt);
		if(fmt[-1] != '\n')
			(void)fputc('\n', stderr);
    }
#endif

    return;
}


void INFO(const char *fmt,...)
{
#ifdef _INFO
	va_list ap;

	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);

	va_end(ap);
	
	if(*fmt){
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
#endif

	return;
}


void error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	if(*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}


void warning(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);

	if(*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}
