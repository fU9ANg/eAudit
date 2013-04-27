/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef CONV_CHARSET_H
#define CONV_CHARSET_H

#include <iconv.h>


/* prototypes. */
int utf8_to_gb2312(char* utf8_char,	  size_t  utf8_len, 			\
		   char* gb2312_char,	  size_t* gb2312_len);
int gb2312_to_utf8(char* gb2312_char,	  size_t  gb2312_len, 			\
		   char* utf8_char,	  size_t* utf_len);
int decode_base64    (char* src,	  size_t  src_len, 			\
		      char* to,		  size_t* to_len);
int unicode_to_gb2312(char* unicode_char, size_t  unicode_len, 			\
		      char* gb2312_char,  size_t* gb2312_len);

int convert(char*  fromcode,     char* tocode,      char* inbuffer, 		\
	    size_t inbuffer_size,char* outbuffer, size_t* outbuffer_size);

#endif /* CONV_CHARSET_H */
