/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include "charset.h"


/*
function name:convert

parameter list:
fromcode		:in
tocode			:in
inbuffer		:in
inbuffer_size	:in
outbuffer		:out
outbuffer_size	:out

*/
/*
int main(int argc, char** argv)
{

	char gb2312_char[10];
	size_t gb2312_len = 10;
	if( utf8_to_gb2312("\347\232\204\344\275\277\347\224\250", 9, gb2312_char, &gb2312_len) != -1)
	{
		printf("%s\n", gb2312_char);
	}

	char* src = "fgIAAAMAAAA5RgYAAAAAAAEAAABtAHMAbgAgAHQAcgBhAG4AcwBmAGUAcgAgAGYAaQBsAGUALgBjAGEAc";
	//	fgIAAAMAAAAAAQAAAAAAAAEAAAB0AGgAhHZ/Tyh1LgB0AHgAdAAAAAAAAAAAAAAAA";
		//fgIAAAMAAAD/AAAAAAAAAAEAAAB0AGgAhHZ/Tyh1LgB0AHgAdAAAAAAAAAAAAAAAA";
	//	"fgIAAAMAAAAQAAAAAAAAAAEAAAB0AGgAhHZ/Tyh1LgB0AHgAd";
	//	fgIAAAMAAAALAAAAAAAAAAEAAAB0AGgAhHZ/Tyh1LgB0AHgAdAAAAAAAAAAAAAAAA";
	//	fgIAAAMAAAAKAAAAAAAAAAEAAAB0AGgAhHZ/Tyh1LgB0AHgAdAAAAAAAAAAAAAAAA";
	//	fgIAAAMAAAAJAAAAAAAAAAEAAAB0AGgAhHZ/Tyh1LgB0AHgAdAAAAAAAAAAAAAAAA";
		//fgIAAAMAAAACAAAAAAAAAAEAAAB0AGgAhHZ/Tyh1LgB0AHgAdAAAAAAAAAAAAAAAA";
		//fgIAAAMAAAABAAAAAAAAAAEAAAB0AGgAhHZ/Tyh1LgB0AHgAdAAAAAAAAAAAAAAAA";
		//"fgIAAAMAAAAAAAAAAAAAAAEAAAB0AGgAhHZ/Tyh1LgB0AHgAdAA";
		//fgIAAAMAAAD/wQAAAAAAAAEAAABNAFMATgCfU0hyLgByAGEAcgAAA";
//		fgIAAAMAAABNDAAAAAAAAAEAAAB0AGgAhHZ/Tyh1LgB0AHgAdAAAAAAAAAAAAAAAA";
//		fgIAAAMAAAAAAAAAAAAAAAEAAAB0AGgAaQBzAGkAcwBhAHQAZQBzAHQAZgBpAGwAZQAAAAAAAAAAAAAAAA";
	//	"fgIAAAMAAAD1twIAAAAAAAEAAABNAFMATgDzl5GYxomRmKROQW3Hjwt6BlKQZy4AcABkAGY";
		//fgIAAAMAAAAoZAAAAAAAAAAAAAAxADUAXwAyADQAMQAwAC4AZwBpAGYAAAAAAAA";
		
		
//		ewAwADQAMgA1AEUANwA5ADcALQA0ADkARgAxAC0ANABEADMANwAtADkAMAA5AEEALQAwADMAMQAxADEANgAxADEAOQBEADkAQgB9AA==";
	int src_len = strlen(src);
	char* to = (char*)malloc(src_len);
	int to_len = src_len;
	int i;
	if(decode_base64(src, src_len, to, &to_len) == -1)
	{
		fprintf(stderr, "decode_base64 fail.\n");
		return -1;
	}
	printf("\n\n");
	for(i = 0; i< to_len; i++)
	{
		printf("%.2X.", (unsigned char)to[i]);
	}
	printf("\n", to_len);
	int j;
	for(i = 0, j = 0; i < to_len - 2; i+=2)
	{
		if(to[i] != 0x00 || to[i+1] != 0x00)
		{
			to[j++] = to[i];
			to[j++] = to[i+1];
		}
	}
	to[j++] = 0x00;
	to[j] = 0x00;


	for(i = 0; i <= j; i++)
	{
		printf("%.2X.", (unsigned char)to[i]);
	}
	printf("\n");
	
	for(i =0; i< j; i++)
	{
		printf("%c", to[i]);
	}

	int gb2312_len = 200;
	char* gb2312_char = malloc(gb2312_len);

	unicode_to_gb2312(to+20, 50, gb2312_char, &gb2312_len);
	

//	utf8_to_gb2312(to, to_len, gb2312_char, &gb2312_len);
//	printf("%d", gb2312_len);
	gb2312_char[gb2312_len] = 0x00;
	setenv("LC_ALL", "C", 1);
	printf("%s", gb2312_char);
	printf("\n");

	return 0;
}
*/


/* implementation for convert procedure. */
	int
utf8_to_gb2312(
	char*	utf8_char,
	size_t  utf8_len,
	char*	gb2312_char,
	size_t* gb2312_len
	)
{

	return convert("UTF8", "GB2312", utf8_char, utf8_len, 			\
			gb2312_char, gb2312_len);
}


	int
gb2312_to_utf8(
	char*	gb2312_char,
	size_t  gb2312_len,
	char*	utf8_char,
	size_t* utf8_len
	)
{

	return convert("GB2312", "UTF8", gb2312_char, gb2312_len,		\
			utf8_char, utf8_len);
}

	int
unicode_to_gb2312(
	char*	unicode_char,
	size_t	unicode_len,
	char*	gb2312_char,
	size_t* gb2312_len
	)
{
	return convert("UNICODE", "GB2312", unicode_char, unicode_len,		\
			gb2312_char, gb2312_len);
}

	int
convert(char*	fromcode,
	char*	tocode,	
	char*	inbuffer,
	size_t	inbuffer_size,	
	char*	outbuffer,
	size_t* outbuffer_size
	)
{
	iconv_t	cd;
	size_t	no_reverse;
	size_t	tmp_size = *outbuffer_size;

	memset(outbuffer, 0x00, *outbuffer_size);
	if((cd = iconv_open(tocode, fromcode)) == (iconv_t)(-1)) {

		if(errno == EINVAL)
			fprintf(stderr, "unsupported conversion.\n");
		return(-1);
	}
	if((no_reverse=iconv(cd, &inbuffer, &inbuffer_size, 			\
			&outbuffer, &tmp_size)) == (size_t)(-1)) {

		switch(no_reverse) {

			case E2BIG:
				fprintf(stderr, "Insufficient outbuffer.\n");
				break;
			case EILSEQ:
				fprintf(stderr, "Invalid multibyte in inbuffer.\n");
				break;
			case EINVAL:
				fprintf(stderr, "An incomplete multibyte in inbuffer.\n");
				break;
			default:
				perror("iconv error");
		}
		return(-1);
	}
	*outbuffer_size -= tmp_size;

	return(iconv_close(cd));
}

	int
decode_base64(
	char*	src,
	size_t	src_len,
	char*	to,
	size_t* to_len
	)
{
	int	i = 0, j;
	int 	e = 0;
	size_t	len;
	unsigned char* src_code;

	if(!(src_code = (unsigned char*)malloc(src_len))) return(-1);

	while(i < src_len) {

		if(src[i] >= 'A' && src[i] <=  'Z')
			src_code[i] = src[i] - 'A';
		else if(src[i] >= 'a' && src[i] <= 'z')
			src_code[i] = src[i] - 'a' + 26;
		else if(src[i] >= '0' && src[i] <= '9')
			src_code[i] = src[i] - '0' + 26 + 26;
		else if(src[i] == '+')
			src_code[i] = 62;
		else if(src[i] == '/')
			src_code[i] = 63;
		else if(src[i] == '=') {

			e++;
			src_code[i] = 0x00;
		} else {

			free(src_code);
			return(-1);
		}
		i++;
	}

	for(i = 0; i < src_len; i++ )
		printf("%.2X ",src_code[i]);
	printf("\n");

	len = src_len * 3/4 - e;
	if(*to_len < len)
		return(-1);
	for(i = 0; i < src_len; i += 4) {

		j = i * 3 / 4;	
		to[j] = (src_code[i]<<2) | (src_code[i+1] >>4);
		to[j+1] = (src_code[i+1]<<4) | (src_code[i+2]>>2);
		to[j+2] = (src_code[i+2]<<6) | (src_code[i+3]); 
	}
	*to_len = len;
	free(src_code);
	return(0);
}
