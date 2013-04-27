/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_CONFIG_H
#define ANALYZE_CONFIG_H

#include "interface.h"

/*
 * define some config options
 * for database.
 */

#define CFG_BLK_SIZE 				63
#define GET_CFG_VAL_FAIL   			1
#define GET_CFG_VAL_OK     			0

#define NOT_EXIST 				0
#define IS_EXIST				1

#define MONITOR_CFG_SECT			"MONITOR_CFG"
#define CONN_INTERVAL				"Conn_Interval"
#define CONN_THRESHOLD				"Conn_Threshold"
#define FLUX_INTERVAL				"Flux_Interval"
#define FLUX_THRESHOLD				"Flux_Threshold"

/* how to read db config */
typedef enum 
{
    DEF_MODE = 0,         
    READ_FILE           
}EN_GET_CFG_MODE;


/* prototypes. */

/* int get_monitor_cfg_info(	\
	EA_MONITOR_INFO_ID monitor_info_id,
	char*		   file_path); */

int get_read_cfg_mode   (	\
	char* 		   file_path,
	int * 		   fd_ptr,
	unsigned long* 	   file_size_ptr);

char* cfg_get_file_cnt  (	\
	int		   fd,
	char* 		   buffer,
	int		   size);

int cfg_get_key_val     (	\
	char*		   src,
	char* 		   seckey,
	char* 		   key,
	char* 		   dest,
	int		   dest_len);


#endif /* ANALYZE_CONFIG_H */
