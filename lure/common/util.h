#ifndef _UTIL_H_
#define _UTIL_H_

#include "unistd.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <assert.h>
#include <regex.h>
#include <stdbool.h>
#include <netdb.h>
#include "ConfigINI.h"
#include "common.h"

//#include "log.h"

#define TIME_MAXLEN 20
#define MAC_MAXLEN 18
#define DEVICE "eth0.2"

typedef void (*sighandler_t)(int);
int ts_to_time(const time_t* ts, char* time);
int time_now(char* time);
int get_mac(const char* dev, unsigned char* mac, int len);
int get_mac_formatted(const char* dev, char* mac_formatted, char c_format);
int mac_formatted(const unsigned char* raw_mac, char* mac_formatted, char c_format);
int get_configmac(char* mac);
int read_file(const char *fileName, int  read_len, char *filebuf);
int write_file(const char *fileName, const char *filebuf);
int system_popen(const char *cmd, char mode, char *result, char *data);
int system_shell(const char *cmd);
char * l_trim(char * strOutput, const char *strInput);
char *r_trim(char *strOutput, const char *strInput);
char * a_trim(char * szOutput, const char * strInput);
int strToUpper(char *str);
int strToLower(char *str);
char * strsep(char **stringp, const char *delim);
char *strnstr(const char *s1, const char *s2, size_t len);
char* memstr(char* mem_data, int mem_data_len, char* substr);
char* strrev(char* s);
void urldecode(char *p);

extern int get_ip(char* eth, int nLen, struct in_addr* ip);

inline void strrpl(char *str);
bool regex_match(const char *pattern, const char *text);
char *getIPbyhost(const char *host, char *ip_addr);
extern int des_encrypt(unsigned char *data, int data_len, unsigned char *key_str, unsigned char *ivec_str, int mode, unsigned char *buf);
extern int des_general(unsigned char *data, int data_len, unsigned char *key_str, unsigned char *ivec_str, int mode, unsigned char *buf);
#endif
