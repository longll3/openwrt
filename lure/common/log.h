#ifndef _LOG_H
#define _LOG_H
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#define MAX_SIZE (1024*1024) //max size of singal log file
#define LINE_SIZE 1000      //max size for each time when read a line from file
#define MSG_MAX_LEN 1024*100  //max length of per message
#define LOG_PATH "/tmp/"
/*APPENDER_TYPE
 0=>both console and file
 1=>only console
 2=>only file
*/
#define APPENDER_TYPE 0
#define MAX_NUMBER 10 //max number of log files

//Determines whether the character c to the digital
#define is_digit(c) ((c) >= '0' && (c) <= '9')
#define ZEROPAD 1               /* pad with zero */
#define SIGN    2               /* unsigned/signed long */
#define PLUS    4               /* show plus */
#define SPACE   8               /* space if plus */
#define LEFT    16              /* left justified */
#define SMALL   32              /* Must be 32 == 0x20 */
#define SPECIAL 64              /* 0x */

#define __do_div(n, base) ({ \
int __res; \
__res = ((unsigned long) n) % (unsigned) base; \
n = ((unsigned long) n) / (unsigned) base; \
__res; })

#define printf(msg, args...){\
    logger("info", __FILE__, __FUNCTION__, __LINE__, msg, ##args);\
}
#define printf(msg, args...){\
    logger("error", __FILE__, __FUNCTION__, __LINE__, msg, ##args);\
}
#define log_debug(msg, args...){\
    logger("debug", __FILE__, __FUNCTION__, __LINE__, msg, ##args);\
}
#define printf(msg, args...){\
    logger("warn", __FILE__, __FUNCTION__, __LINE__, msg, ##args);\
}

char FILE_LOG[64];
int logger_init(const char* fileName);
void logger(const char* level, const char* file, const char* function, int line, const char* msg, ...);
int Backup(const char *dstFile, const char *srcFile);
int change_name(const char *dstFile, const char *srcFile);
static int skip_atoi(const char **s);
static char *number(char *str, long num, int base, int size, int precision, int type);
static int log_buf(char *buf, const char *fmt, va_list args);

void log_hex(unsigned char *msg, int len, char *tips);
#endif // _LOG_H

