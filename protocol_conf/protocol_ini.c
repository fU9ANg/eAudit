
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "protocol_ini.h"


/**********************************
*func name: rightTrim
*function: ȥ���ַ����ұߵĿ��ַ�
*parameters:
		�������: src: ԭʼ�ַ���
		�������: src: ȥ���ұ߿ո����ַ���
*call:
*called:
*return: ��
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
*function: ȥ���ַ�����ߵĿ��ַ�
*parameters: 
			�������: src: ԭʼ�ַ���
			�������: src: ȥ����߿ո����ַ���
*call:
*called:
*return: ��
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
*function: ȥ���ַ������ҵĿ��ַ�
*parameters:
		�������: src: ԭʼ�ַ���
		�������: src: ȥ�����ҿո����ַ���
*call:
*called:
*return: 
		TRUE: �����ɹ�
		FALSE: ����ʧ��
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
*function: ���������������src�����±������������Ľ�������dst��
		   ����: src = {10,9,15,20,1,13,4,6,25,4}, len=10
		   �����dst = {4,6,9,7,1,0,5,2,3,8}
*parameters:
		�������: src: ������������
				  len: ����src�ĳ��Ⱥ�����dst�ĳ��ȶ�Ϊlen
		�������: dst: �±������Ľ��
*call:
*called:
*return: 
		TRUE: �����ɹ�
		FALSE: ����ʧ��
*/
int sortIndex (const int *src, int *dst, int len)
{
	int i, j;
	int k = 0;
	int min = 0;
	unsigned char *pFlag = NULL;//���ڱ�ʶ�����ĳ��Ԫ���Ƿ��������Ϊ0x00��ʾδ������


	if (NULL == src || NULL == dst || len <= 0)
		return FALSE;

	pFlag = calloc(sizeof(unsigned char), len);
	if (NULL == pFlag)
		return FALSE;


	for (i=0; i<len; i++)
	{
		//���ȴ����鿪ͷ�ҵ�û�б��������Ԫ��, ��¼���±�
		for (j=0; j<len; j++)
		{
			if (pFlag[j] == 0x00)
			{
				k = j;
				min = src[j];
				break;
			}
		}

		//�������飬����û�б��������Ԫ������С�ģ�����¼���±�
		for (j=k; j<len; j++)	//��һ�����޸�!!!!!!!!!!!!!!!!!!!!!!
		{
			if ((pFlag[j] == 0x00) && (min > src[j]))
			{
				k = j;
				min = src[j];
			}
		}

		//��ʶ����ѭ�����ҵ�����СԪ�ر������, ���Ѹ�Ԫ�ص��±����
		pFlag[k] = 0xff;
		dst[i] = k;
	}

	free(pFlag);
	pFlag = NULL;
	return TRUE;
}


/**********************************
*func name: cfgGetSection
*function: �������ļ���һ����������ȡsection ��
*parameters:
		�������: pcLineBuf�������ļ���һ������
		�������: pcSection����ȡ����section��
*call:
*called:
*return:
*/
int cfgGetSection(char *pcLineBuf, char *pcSection)
{
	char *pcEnd;


	if ((NULL == pcLineBuf) || (NULL == pcSection))
		return FALSE;

	trim(pcLineBuf);	//ȥ���л������ҵĿ��ַ�

	//�����һ���ַ�����'[', �������һ���ַ�����']', ���������м�û���ַ�������ʧ��
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
*function: �������ļ���ȡ����Ϊsection������Ϊkey���������ֵ�������val�С�
		   ���sectionΪNULL�����ļ�ָ�뵱ǰλ�ö�ȡ����Ϊkey���������ֵ�������val��
*parameters:
		�������: fp: �����ļ�FILEָ��
		          section: ����
        		  key: ����
            	  vallen: �������val�Ĵ�С�������ȡ���ļ�ֵ���ȴ���val�����ش���
		�������: val: ��ȡ���ļ�ֵ
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

	//���sectionΪ�գ�������δ��룬�������ļ�������key=val
	//���section��Ϊ�գ����ļ���ʼ�������ļ�����ȡ��section�У�Ȼ��������ļ�������key=val
	if (section != NULL)
	{
		if (strlen(section) <= 0)
			return FALSE;

		fseek(fp, 0, SEEK_SET);

		while (1)
		{
			memset(szLineBuf, 0x00, sizeof(szLineBuf));
			if (NULL == fgets(szLineBuf, MAX_LINE_BUF, fp)) //��ȡ����һ������
				return FALSE;
			
			if (FALSE == cfgGetSection(szLineBuf, szSectionBuf)) //����section��
				continue;

			if (strcmp(szSectionBuf, section) != 0)	//���Ǹ�section
				continue;
			else	//�ҵ��˸�section
				break;
		}
	}



	while (1)
	{//��ȡkey������ļ�ֵ
		char *pEqual, *pKeyCur, *pValCur, *pTmp;

		memset(szLineBuf, 0x00, sizeof(szLineBuf));
		if (NULL == fgets(szLineBuf, MAX_LINE_BUF, fp))
			return FALSE;

		if (TRUE == cfgGetSection(szLineBuf, szSectionBuf))
			return FALSE;


		pEqual = strchr(szLineBuf, '=');
		if(NULL == pEqual)
			continue;

		*pEqual = '\0';    //��'='  �滻���ַ���������־'\0', �����ּ����ͼ�ֵ
		pKeyCur = szLineBuf;

		if(trim(pKeyCur) != TRUE)
			continue;

		if (strcmp(pKeyCur, key) != 0)
			continue;

		//ȡ��val��ֵ�������
		pValCur = pEqual+1;

		if(trim(pValCur) != TRUE)
			return FALSE;

		//ȥ����ֵ����';'
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
*function: �������ļ�˳���ȡ����Ϊsection���������У������ͼ�ֵ���ֱ𱣴���key��val
		   ���sectionΪNULL�����ļ�ָ�뵱ǰλ�ö�ȡ����Ϊkey���������ֵ�������val��
*parameters:
		�������: fp: �����ļ�FILEָ��
				  section: ����
				  keylen: �������key�Ĵ�С�������ȡ���ļ������ȴ���keylen�����ش���
				  vallen: �������val�Ĵ�С�������ȡ���ļ�ֵ���ȴ���vallen�����ش���
		�������: key: ��������
				  val: ��ֵ����
*call:
*called:
*return: FALSE: ʧ��
  		 EXCEED_BUF_LEN: ����ȡ��keyֵ���ȴ���keylen����valֵ���ȴ���vallen
  		 TRUE: �ɹ�

*/
int  cfgGetItemValue(FILE *fp, const char *section, char *key, int keylen, char *val, int vallen)
{
	char szLineBuf[MAX_LINE_BUF];
	char szSectionBuf[MAX_SECTION_BUF];


	if (NULL == fp || NULL == key || keylen <= 0 || NULL == val || vallen <= 0)
		return FALSE;

	//���sectionΪ�գ�������δ��룬�������ļ�������key=val
	//���section��Ϊ�գ����ļ���ʼ�������ļ�����ȡ��section�У�Ȼ��������ļ�������key=val
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
			
			if (FALSE == cfgGetSection(szLineBuf, szSectionBuf))	//����section��
				continue;

			if (strcmp(szSectionBuf, section) != 0)	//���Ǹ�section
				continue;
			else	//�ҵ��˸�section
				break;
		}
	}


	while (1)
	{//��ȡkey������ļ�ֵ
		char *pEqual, *pKeyCur, *pValCur, *pTmp;

		memset(szLineBuf, 0x00, sizeof(szLineBuf));
		if (NULL == fgets(szLineBuf, MAX_LINE_BUF, fp))
			return FALSE;

		if (TRUE == cfgGetSection(szLineBuf, szSectionBuf))
			return FALSE;


		pEqual = strchr(szLineBuf, '=');
		if(NULL == pEqual)
			return FALSE;

		*pEqual = '\0';    //��'='  �滻���ַ���������־'\0', �����ּ����ͼ�ֵ
		pKeyCur = szLineBuf;
		pValCur = pEqual+1;

		if(trim(pKeyCur) != TRUE || trim(pValCur) != TRUE)
			continue;

		pTmp = pValCur + strlen(pValCur) - 1;	//ȥ����ֵ����';'
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
*function: ȡ�������ļ���LIST_NUM��ֵ�������listnum�С�
		   �ٶ�LIST_NUM��ֵ�ǲ�����99λ��ʮ��������������򷵻�ʧ��
*parameters:
		�������: fp: �����ļ�FILEָ��
		�������: int *listnum: �����ļ��������б�����
*call:
*called:
*return: FALSE: ʧ��
		 EXCEED_BUF_LEN: ���������Ȳ���
		 TRUE: �ɹ�
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
*function: ȡ�������ļ���MODE_GETE��ֵ�������modegete�С�
		   �ٶ�MODE_GETE��ֵ�ǲ�����99λ���ַ���������򷵻�ʧ��
*parameters:
		�������: fp: �����ļ�FILEָ��
		�������: int *modegete: �����ļ���ģʽֵ
*call:
*called:
*return: FALSE: ʧ��
		 EXCEED_BUF_LEN: ���������Ȳ���
		 TRUE: �ɹ�
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
*function: ȡ�������ļ��������б��ֵ�������listinfo��
*parameters:
		�������: FILE *fp: �����ļ�FILEָ��
				  int itemlen: �����б���ĳ���
				  int listnum: �����б��С
		�������: char *listinfo: �����б�
*call:
*called:
*return: FALSE: ʧ��
		 TRUE: �ɹ�
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


