/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdlib.h>

#include "eAudit_mem.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void SAIL_free(void **ptr)
{
	if(*ptr != NULL)/*¼ÓÓÚ2009-4-7*/
	{
		free(*ptr);
		*ptr = NULL;
	}
}
