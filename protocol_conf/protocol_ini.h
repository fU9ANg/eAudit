
#ifndef _PROTOCOL_INI_H
#define _PROTOCOL_INI_H

#include <stdio.h>

#ifndef TRUE
#define TRUE			1
#endif
#ifndef FALSE
#define FALSE			0
#endif
#ifndef EXCEED_BUF_LEN
#define EXCEED_BUF_LEN	-1
#endif

#define MAX_LINE_BUF 512 //定义行缓存大小,即配置文件一行数据字符个数的上限(包括回车换行和结束符)
#define MAX_SECTION_BUF 50 //定义section的最大字节数

#define COMMON_SECTION		"COMMON"
#define LIST_INFO_SECTION	"LIST_INFO"
#define LIST_NUM_KEY		"LIST_NUM"
#define LIST_MODE_GETE_KEY	"MODE_GETE"
#define LIST_RESOURCE_KEY	"INFO"


/**********************************
*func name: sortIndex
*function: 对输入的整形数组src按照下标进行排序，排序的结果存放在dst中
		   例如: src = {10,9,15,20,1,13,4,6,25,4}, len=10
		   排序后dst = {4,6,9,7,1,0,5,2,3,8}
*parameters:
		输入参数: src: 输入整形数组
				  len: 数组src的长度和数组dst的长度都为len
		输出参数: dst: 下标排序后的结果
*call:
*called:
*return: 
		TRUE: 操作成功
		FALSE: 操作失败
*/
int sortIndex (const int *src, int *dst, int len);

/**********************************
*func name: cfgGetSection
*function: 从配置文件的一行数据中提取section 名
*parameters:
		输入参数: pcLineBuf，配置文件的一行数据
		输出参数: pcSection，提取出的section名
*call:
*called:
*return:
*/
int cfgGetSection(char *pcLineBuf, char *pcSection);

/**********************************
*func name: cfgGetKeyValue
*function: 从配置文件读取节名为section，键名为key的配置项的值，存放在val中。
		   如果section为NULL，从文件指针当前位置读取键名为key的配置项的值，存放在val中
*parameters:
		输入参数: fp: 配置文件FILE指针
		          section: 节名
        		  key: 键名
            	  vallen: 输出缓冲val的大小，如果获取到的键值长度大于val，返回错误
		输入参数: val: 获取到的键值
*call:
*called:
*return:
*/
int  cfgGetKeyValue(FILE *fp, const char *section, const char *key, char *val, int vallen);

/**********************************
*func name: cfgGetItemValue
*function: 从配置文件顺序读取节名为section的配置项中，键名和键值，分别保存于key和val
		   如果section为NULL，从文件指针当前位置读取键名为key的配置项的值，存放在val中
*parameters:
		输入参数: fp: 配置文件FILE指针
				  section: 节名
				  keylen: 输出缓冲key的大小，如果获取到的键名长度大于keylen，返回错误
				  vallen: 输出缓冲val的大小，如果获取到的键值长度大于vallen，返回错误
		输出参数: key: 键名缓冲
				  val: 键值缓冲
*call:
*called:
*return: FALSE: 失败
  		 EXCEED_BUF_LEN: 待获取的key值长度大于keylen或者val值长度大于vallen
  		 TRUE: 成功

*/
int  cfgGetItemValue(FILE *fp, const char *section, char *key, int keylen, char *val, int vallen);

/**********************************
*func name: cfgGetListNum
*function: 取得配置文件中LIST_NUM的值，存放在listnum中。
		   假定LIST_NUM的值是不超过99位的十进制数，否则程序返回失败
*parameters:
		输入参数: fp: 配置文件FILE指针
		输出参数: int *listnum: 配置文件中配置列表数量
*call:
*called:
*return: FALSE: 失败
		 EXCEED_BUF_LEN: 缓冲区长度不够
		 TRUE: 成功
*/
int  cfgGetListNum(FILE *fp, int *listnum);

/**********************************
*func name: cfgGetModegete
*function: 取得配置文件中MODE_GETE的值，存放在modegete中。
		   假定MODE_GETE的值是不超过99位的字符，否则程序返回失败
*parameters:
		输入参数: fp: 配置文件FILE指针
		输出参数: int *modegete: 配置文件中模式值
*call:
*called:
*return: FALSE: 失败
		 EXCEED_BUF_LEN: 缓冲区长度不够
		 TRUE: 成功
*/
int  cfgGetModegete(FILE *fp, int *modegete);

/**********************************
*func name: cfgGetListInfo
*function: 取得配置文件中配置列表的值，存放在listinfo中
*parameters:
		输入参数: FILE *fp: 配置文件FILE指针
				  int itemlen: 配置列表项的长度
				  int listnum: 配置列表大小
		输出参数: char *listinfo: 配置列表
*call:
*called:
*return: FALSE: 失败
		 TRUE: 成功
*/
int  cfgGetListInfo(FILE *fp, char *listinfo, int itemlen, int listnum);

#endif
