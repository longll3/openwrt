#ifndef _CONFIGINI_H
#define _CONFIGINI_H
#include <semaphore.h>
#include <fcntl.h>

#define KEYVALLEN 100
#define CONFIGFILE "/root/config.ini"

#define SECT_LEN 32
#define KEY_LEN 32
#define VAL_LEN 100
#define SEM_NAME "config_sem"	//¨ª?2?D?o???3?

typedef struct Str_KeyVal{
	struct Str_KeyVal *next;
	char section[SECT_LEN];
    char key[KEY_LEN];
    char val[VAL_LEN];
} str_keyVal;
//???t2¨´¡Á¡Â¨ª?2?D?o?
extern sem_t* file_sem;

//3?¨º??¡¥?????¡ê?¨¦
extern int initConfig();

int GetProfileString(const char *profile, const char *AppName, const char *KeyName, char *KeyVal );
int WriteProfileString(const char *fileName, const char *sectionName, const char *keyName, const char *value);
int BackupConfig(const char *dstFile, const char *srcFile);
int GetAllConfig(const char *fileName, str_keyVal **kvp);
int WriteAllConfig(const str_keyVal *keyvalptr, const char *fileName);
int Traverse_search(const str_keyVal *keyvalptr, const char *section, const char *key, str_keyVal **kvp);
int setConfig(const str_keyVal *keyvalptr, const char *section, const char *key, const char *value);
int getConfig(const str_keyVal *keyvalptr, const char *section, const char *key, char *value);

#endif
