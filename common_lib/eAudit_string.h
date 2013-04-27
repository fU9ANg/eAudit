/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EADUIT_STRING_H
#define _EADUIT_STRING_H

extern size_t strlcpy(char *dst, const char *src, size_t siz);
extern void left_trim(char *src);
extern void right_trim(char *src);
extern void trim(char *src);
extern char *quick_trim(char *src);

#endif
