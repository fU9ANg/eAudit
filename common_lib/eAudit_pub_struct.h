#ifndef _EAUDIT_PUB_STRUCT_H
#define _EAUDIT_PUB_STRUCT_H


/*审计级别定义*/
typedef struct tagEAUDIT_LEVEL
{
	unsigned char eaudit_direction;
	unsigned char session_level;
	unsigned char record_level;
	unsigned char event_level;
	unsigned char analysis_level;
	unsigned char total_analysis_level;
	unsigned char custom_made_level;
	unsigned char manage_level;
}   EAUDIT_LEVEL,*EAUDIT_LEVEL_ID;
#define eaudit_level_size sizeof(EAUDIT_LEVEL)



/*报警级别定义*/
typedef struct tagNOT_AUTHORIZE_EVENT
{
	unsigned char block_flag;
	unsigned char warn_flag;
	unsigned char log_flag;
}   NOT_AUTHORIZE_EVENT,*NOT_AUTHORIZE_EVENT_ID;
#define not_authorize_event_size sizeof(NOT_AUTHORIZE_EVENT)


/*授权关系列表结构体定义*/
typedef struct tagAUTHORIZE_LEVEL
{
	unsigned char  authorize_account;
	unsigned char  authorize_cmd;
	unsigned char  authorize_custom_made;
	unsigned char authorize_pro_feature_made;
}   AUTHORIZE_LEVEL,*AUTHORIZE_LEVEL_ID;
#define authorize_level_size sizeof(AUTHORIZE_LEVEL)

#endif
