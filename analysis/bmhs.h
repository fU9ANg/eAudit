/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_BMHS_H
#define ANALYZE_BMHS_H

#define MAX_BMHS_CH_NUM			256

/* prototypes. */
void make_shift(unsigned char *patt, int *shift, int patt_size);
int  mem_search(unsigned char *text, int len, unsigned char *patt, 		\
		int patt_size, int *shift);
int  mem_find  (const void *in_block, int block_size, const void *in_pattern, 	\
		int pattern_size, int *shift);
void *txt_find (const void *in_block, int block_size, const void *in_pattern, 	\
		int pattern_size, int *shift, int *init);


#endif /* ANALYZE_BMHS_H */
