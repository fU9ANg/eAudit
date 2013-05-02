
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

#define MAX_LINE_BUF 512 //�����л����С,�������ļ�һ�������ַ�����������(�����س����кͽ�����)
#define MAX_SECTION_BUF 50 //����section������ֽ���

#define COMMON_SECTION		"COMMON"
#define LIST_INFO_SECTION	"LIST_INFO"
#define LIST_NUM_KEY		"LIST_NUM"
#define LIST_MODE_GETE_KEY	"MODE_GETE"
#define LIST_RESOURCE_KEY	"INFO"


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
int sortIndex (const int *src, int *dst, int len);

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
int cfgGetSection(char *pcLineBuf, char *pcSection);

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
int  cfgGetKeyValue(FILE *fp, const char *section, const char *key, char *val, int vallen);

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
int  cfgGetItemValue(FILE *fp, const char *section, char *key, int keylen, char *val, int vallen);

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
int  cfgGetListNum(FILE *fp, int *listnum);

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
int  cfgGetModegete(FILE *fp, int *modegete);

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
int  cfgGetListInfo(FILE *fp, char *listinfo, int itemlen, int listnum);

#endif
