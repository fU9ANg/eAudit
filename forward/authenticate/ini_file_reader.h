#ifndef INI_FILE_READER_H
#define INI_FILE_READER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INI_ITEM_NAME_LEN		64
#define INI_ITEM_VALUE_LEN		128

#ifndef true
typedef char  bool;
#define true  1
#define false 0
#endif


typedef struct
{
	char name[INI_ITEM_NAME_LEN + 1];
	char value[INI_ITEM_VALUE_LEN + 1];
} IniItemInfo;

#ifdef __cplusplus
extern "C" {
#endif

int iniLoadItems(const char *szFilename, IniItemInfo **ppItems, \
			int *nItemCount);

void iniFreeItems(IniItemInfo *items);

char *iniGetStrValue(const char *szName, IniItemInfo *items, \
			const int nItemCount);
int iniGetValues(const char *szName, IniItemInfo *items, const int nItemCount, \
			char **szValues, const int max_values);

int iniGetIntValue(const char *szName, IniItemInfo *items, \
			const int nItemCount, const int nDefaultValue);
int64_t iniGetInt64Value(const char *szName, IniItemInfo *items, \
			const int nItemCount, const int64_t nDefaultValue);
bool iniGetBoolValue(const char *szName, IniItemInfo *items, \
		const int nItemCount);

#ifdef __cplusplus
}
#endif

#endif

