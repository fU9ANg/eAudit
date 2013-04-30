
#ifndef CAPTURE_CONFIG_H
#define CAPTURE_CONFIG_H


/*DB�û��������ݿ�������󳤶�*/

/*���ݿ�����������*/

#define CFG_BLK_SIZE 				63
#define GET_CFG_VAL_FAIL   			1
#define GET_CFG_VAL_OK     			0



#define NOT_EXIST 					0
#define IS_EXIST						1

/*��ȡ�����ļ��ķ�ʽ*/
typedef enum 
{
    DEF_MODE = 0,         
    READ_FILE           
}EN_GET_CFG_MODE;

int get_read_cfg_mode(char *file_path,int *fd_ptr,unsigned long *file_size_ptr);
char * cfg_get_file_cnt1 (int fd,char *buffer,int size);
int cfg_get_key_val1(char *src,char *seckey, char *key,char *dest, int dest_len);



#endif
