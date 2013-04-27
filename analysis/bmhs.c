/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdlib.h>
#include <ctype.h>

#include "bmhs.h"


void make_shift(
	unsigned char*	patt,
	int*		shift,
	int		patt_size
	)
{
   int i;

   for (i = 0;i < MAX_BMHS_CH_NUM;i++)
       *(shift+i)=patt_size + 1;
   
   for (i = 0;i < patt_size;i++)
       *(shift + (unsigned char)(*(patt+i) ) ) = patt_size - i;

   return;
}


/*
 * 大小写敏感的	字符串匹配算法
 */
int mem_search(
	unsigned char*	text,
	int		len,
	unsigned char*	patt,
	int		patt_size,
	int*		shift
	)
{
	
    int	i, limit,  match_size, text_size = len;
    unsigned char* match_text;

    limit = text_size - patt_size + 1;
    for (i = 0;i < limit;i += shift[text[i + patt_size] ] ) {

        if (text[i] == *patt) {

            match_text = (unsigned char*)text + i + 1;
            match_size = 1;

            do{
                if(match_size == patt_size)
                    return i;
            }while( (*match_text++) == patt[match_size++] );
        }
    }

    return(-1);
}


/*
 *  大小写不敏感的  字符串匹配算法
 */
int
mem_find(
	const void*	in_block,
	int		block_size,
	const void*	in_pattern,
	int		pattern_size,
	int*		shift
	)
{                   
    int byte_nbr, match_size, limit;
    const unsigned char *match_ptr = NULL;
    const unsigned char *block =  (unsigned char *) in_block,   
                                  *pattern = (unsigned char *) in_pattern;    

    if (block == NULL || pattern == NULL || shift == NULL)
        return -1;

    /* 查找的串长应该小于 数据长度*/
    if (block_size < pattern_size)
        return -1;

    /* 空串匹配第一个 */
    if (pattern_size == 0)     
        return 0;

    /*匹配*/
    limit = block_size - pattern_size + 1;
    for (byte_nbr = 0; byte_nbr < limit; byte_nbr += shift[tolower(block[byte_nbr + pattern_size])]) 
    {
        if (tolower(block[byte_nbr]) == tolower(*pattern)) {

            /*
             * 如果第一个字节匹配，那么继续匹配剩下的
             */
            match_ptr  = block + byte_nbr + 1;
            match_size = 1;

            do {
                if (match_size == pattern_size)
                    return(byte_nbr);
            } while (tolower(*match_ptr++) == tolower(pattern[match_size++]));
        }
    }
    
    return(-1);
}


/*
 *  大小写不敏感的  字符串匹配算法
 */
void *txt_find(const void *in_block, int block_size, const void *in_pattern, int pattern_size,  int *shift, int *init)
{                   
    int byte_nbr, match_size, limit;
    const unsigned char* match_ptr = NULL;
    const unsigned char* block 	   = (unsigned char*)in_block; 
    const unsigned char* pattern   = (unsigned char*)in_pattern;    

    if  (block == NULL || pattern == NULL || shift == NULL)
		return(NULL);

    /* 查找的串长应该小于 数据长度*/
    if (block_size < pattern_size)
        return(NULL);

    /* 空串匹配第一个 */
    if (pattern_size == 0)     
        return((void *) block);

    /* 如果没有初始化，构造移位表*/
     if(!init || !*init) {
        for (byte_nbr = 0; byte_nbr < 256; byte_nbr++)
            shift[byte_nbr] = pattern_size + 1;
        for (byte_nbr = 0; byte_nbr < pattern_size; byte_nbr++)
            shift[(unsigned char) tolower(pattern[byte_nbr])] = pattern_size - byte_nbr;

        if (*init)
            *init = 1;
    }

    /*匹配*/
    limit = block_size - pattern_size + 1;
    for (byte_nbr = 0; byte_nbr < limit; byte_nbr += shift[tolower(block[byte_nbr + pattern_size])]) 
    {
        if (tolower(block[byte_nbr]) == tolower(*pattern)) {
            /*
             * 如果第一个字节匹配，那么继续匹配剩下的
             */
            match_ptr = block + byte_nbr + 1;
            match_size = 1;

            do {
                if (match_size == pattern_size)
                    return(void *) (block + byte_nbr);
            } while (tolower(*match_ptr++) == tolower(pattern[match_size++]));
        }
    }
    
    return(NULL);
}

