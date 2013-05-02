
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "protocol_ini.h"


/**********************************
*func name: rightTrim
*function: 去掉字符串右边的空字符
*parameters:
		输入参数: src: 原始字符串
		输出参数: src: 去掉右边空格后的字符串
*call:
*called:
*return: 无
*/
void rightTrim(char *src)
{
    unsigned long i = 0;
    unsigned len = 0;
    register char *str = src;
	
    len = strlen(str);
    i = len-1;

    while(i >= 0)
    {
        if (0 == isspace(str[i]))
        	  break;
        i--;
    }
   
    if (i < len-1)
    	str[i+1] = '\0';
    
    return;      
}

/**********************************
*func name: leftTrim
*function: 去掉字符串左边的空字符
*parameters: 
			输入参数: src: 原始字符串
			输出参数: src: 去掉左边空格后的字符串
*call:
*called:
*return: 无
*/
void leftTrim(char *src)
{
    register char *str = src;
    register char *s = src;
    
    while(*str != '\0')
    {
        if (0 == isspace(*str))
        	  break;     
        str++; 
    }
    
    if (str != s)
    	while((*s++ = *str++) != '\0');
    
    return;
}

/**********************************
*func name: trim
*function: 去掉字符串左右的空字符
*parameters:
		输入参数: src: 原始字符串
		输出参数: src: 去掉左右空格后的字符串
*call:
*called:
*return: 
		TRUE: 操作成功
		FALSE: 操作失败
*/
int trim(char *src)
{
    char *s = src;
	
    if (NULL == src)
    	return FALSE;

    rightTrim(s);
    leftTrim(s);
    return (strlen(s)>0 ? TRUE : FALSE);
}

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
int sortIndex (const int *src, int *dst, int len)
{
	int i, j;
	int k = 0;
	int min = 0;
	unsigned char *pFlag = NULL;//用于标识数组的某个元素是否被排序过，为0x00表示未被排序


	if (NULL == src || NULL == dst || len <= 0)
		return FALSE;

	pFlag = calloc(sizeof(unsigned char), len);
	if (NULL == pFlag)
		return FALSE;


	for (i=0; i<len; i++)
	{
		//首先从数组开头找到没有被排序过的元素, 记录其下标
		for (j=0; j<len; j++)
		{
			if (pFlag[j] == 0x00)
			{
				k = j;
				min = src[j];
				break;
			}
		}

		//遍历数组，查找没有被排序过的元素中最小的，并记录其下标
		for (j=k; j<len; j++)	//这一行有修改!!!!!!!!!!!!!!!!!!!!!!
		{
			if ((pFlag[j] == 0x00) && (min > src[j]))
			{
				k = j;
				min = src[j];
			}
		}

		//标识本次循环查找到的最小元素被排序过, 并把该元素的下标输出
		pFlag[k] = 0xff;
		dst[i] = k;
	}

	free(pFlag);
	pFlag = NULL;
	return TRUE;
}


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
int cfgGetSection(char *pcLineBuf, char *pcSection)
{
	char *pcEnd;


	if ((NULL == pcLineBuf) || (NULL == pcSection))
		return FALSE;

	trim(pcLineBuf);	//去掉行缓存左右的空字符

	//如果第一个字符不是'[', 或者最后一个字符不是']', 或者两者中间没有字符，返回失败
	if (*pcLineBuf != '[')
		return FALSE;

	pcEnd = pcLineBuf + strlen(pcLineBuf) - 1;
	if ((*pcEnd != ']') || ((pcEnd-pcLineBuf) <= 1))
		return FALSE;

	*pcEnd = '\0';
	strcpy(pcSection, pcLineBuf+1);
	return trim(pcSection);
} 

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
int  cfgGetKeyValue(FILE *fp, const char *section, const char *key, char *val, int vallen)
{
	char szLineBuf[MAX_LINE_BUF];
	char szSectionBuf[MAX_SECTION_BUF];


	if (NULL == fp || NULL == key || strlen(key) <= 0 || NULL == val || vallen <= 0)
		return FALSE;

	//如果section为空，跳过这段代码，继续读文件，查找key=val
	//如果section不为空，从文件开始处遍历文件，读取到section行，然后继续读文件，查找key=val
	if (section != NULL)
	{
		if (strlen(section) <= 0)
			return FALSE;

		fseek(fp, 0, SEEK_SET);

		while (1)
		{
			memset(szLineBuf, 0x00, sizeof(szLineBuf));
			if (NULL == fgets(szLineBuf, MAX_LINE_BUF, fp)) //读取配置一行数据
				return FALSE;
			
			if (FALSE == cfgGetSection(szLineBuf, szSectionBuf)) //不是section行
				continue;

			if (strcmp(szSectionBuf, section) != 0)	//不是该section
				continue;
			else	//找到了该section
				break;
		}
	}



	while (1)
	{//提取key项键名的键值
		char *pEqual, *pKeyCur, *pValCur, *pTmp;

		memset(szLineBuf, 0x00, sizeof(szLineBuf));
		if (NULL == fgets(szLineBuf, MAX_LINE_BUF, fp))
			return FALSE;

		if (TRUE == cfgGetSection(szLineBuf, szSectionBuf))
			return FALSE;


		pEqual = strchr(szLineBuf, '=');
		if(NULL == pEqual)
			continue;

		*pEqual = '\0';    //将'='  替换成字符串结束标志'\0', 以区分键名和键值
		pKeyCur = szLineBuf;

		if(trim(pKeyCur) != TRUE)
			continue;

		if (strcmp(pKeyCur, key) != 0)
			continue;

		//取出val的值，并输出
		pValCur = pEqual+1;

		if(trim(pValCur) != TRUE)
			return FALSE;

		//去掉键值最后的';'
		pTmp = pValCur + strlen(pValCur) - 1;
		if (';' == *pTmp)
			*pTmp = '\0';

		if (strlen(pValCur) > vallen)
			return EXCEED_BUF_LEN;

		strcpy(val, pValCur);
		return TRUE;
	}	
}

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
int  cfgGetItemValue(FILE *fp, const char *section, char *key, int keylen, char *val, int vallen)
{
	char szLineBuf[MAX_LINE_BUF];
	char szSectionBuf[MAX_SECTION_BUF];


	if (NULL == fp || NULL == key || keylen <= 0 || NULL == val || vallen <= 0)
		return FALSE;

	//如果section为空，跳过这段代码，继续读文件，查找key=val
	//如果section不为空，从文件开始处遍历文件，读取到section行，然后继续读文件，查找key=val
	if (section != NULL)
	{
		if (strlen(section) == 0)
			return FALSE;

		fseek(fp, 0, SEEK_SET);

		while (1)
		{
			memset(szLineBuf, 0x00, sizeof(szLineBuf));
			if (NULL == fgets(szLineBuf, MAX_LINE_BUF, fp))
				return FALSE;
			
			if (FALSE == cfgGetSection(szLineBuf, szSectionBuf))	//不是section行
				continue;

			if (strcmp(szSectionBuf, section) != 0)	//不是该section
				continue;
			else	//找到了该section
				break;
		}
	}


	while (1)
	{//提取key项键名的键值
		char *pEqual, *pKeyCur, *pValCur, *pTmp;

		memset(szLineBuf, 0x00, sizeof(szLineBuf));
		if (NULL == fgets(szLineBuf, MAX_LINE_BUF, fp))
			return FALSE;

		if (TRUE == cfgGetSection(szLineBuf, szSectionBuf))
			return FALSE;


		pEqual = strchr(szLineBuf, '=');
		if(NULL == pEqual)
			return FALSE;

		*pEqual = '\0';    //将'='  替换成字符串结束标志'\0', 以区分键名和键值
		pKeyCur = szLineBuf;
		pValCur = pEqual+1;

		if(trim(pKeyCur) != TRUE || trim(pValCur) != TRUE)
			continue;

		pTmp = pValCur + strlen(pValCur) - 1;	//去掉键值最后的';'
		if (';' == *pTmp)
			*pTmp = '\0';

		if (strlen(pKeyCur) > keylen || strlen(pValCur) > vallen)
			return EXCEED_BUF_LEN;

		strcpy(key, pKeyCur);
		strcpy(val, pValCur);
		return TRUE;
	}
}

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
int  cfgGetListNum(FILE *fp, int *listnum)
{
	int nRetVal;
	char szListNum[100];

	if (NULL == fp || NULL == listnum)
		return FALSE;

	nRetVal = cfgGetKeyValue(fp, COMMON_SECTION, LIST_NUM_KEY, szListNum, sizeof(szListNum));
	if(nRetVal != TRUE)
		return nRetVal;


	*listnum = atoi(szListNum);
	return TRUE;
}

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
int  cfgGetModegete(FILE *fp, int *modegete)
{
	int nRetVal;
	char szModeGet[100];


	*modegete = 1;

	if (NULL == fp || NULL == modegete)
		return FALSE;

	nRetVal = cfgGetKeyValue(fp, COMMON_SECTION, LIST_MODE_GETE_KEY, szModeGet, sizeof(szModeGet));
	if(nRetVal != TRUE)
		return nRetVal;


	if (strcmp(szModeGet, "ON")==0 || strcmp(szModeGet, "on")==0)
	{
		return TRUE;
	}
	else
	{
		*modegete = 0;
		return TRUE;
	}
}

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
int  cfgGetListInfo(FILE *fp, char *listinfo, int itemlen, int listnum)
{
	int i;
	char szListInfoCur[MAX_LINE_BUF];

	if (NULL == fp || NULL == listinfo || itemlen <= 0 || listnum <= 0)
		return FALSE;

	for (i=0; i<listnum; i++)
	{
		char szKeyTmp[6];

		memset(szKeyTmp, 0x00, sizeof(szKeyTmp));
		memset(szListInfoCur, 0x00, sizeof(szListInfoCur));

		sprintf(szKeyTmp, "INFO%d", i);

	    if (TRUE != cfgGetKeyValue(fp, LIST_INFO_SECTION, szKeyTmp, szListInfoCur, sizeof(szListInfoCur)))
	    	return FALSE;

	    if (strlen(szListInfoCur) > itemlen)
	    	return FALSE;

	    strcpy(listinfo+i*itemlen, szListInfoCur);
	}

	return TRUE;
}


