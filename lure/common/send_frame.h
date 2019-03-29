//
// Created by root on 1/26/19.
//

#ifndef LURE_SEND_FRAME_H
#define LURE_SEND_FRAME_H

#endif //LURE_SEND_FRAME_H

//
// Created by root on 19-1-8.
//

#ifndef YINMEE_SEND_FRAME_H
#define YINMEE_SEND_FRAME_H

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
//#include "semun.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <time.h>
#include <pthread.h>
#include <math.h>
#include <arpa/inet.h>

//#include "upload_pro.h"
#include "msg.h"
//#include "properties.h"
#include "common.h"
#include <signal.h>

#include <asm/byteorder.h>

extern int sk;
extern int socket_tcp;

int getIPAndPort(char *ip, char *tcp_port);
int createSocket();
int formatData(TELEGRAM **telegram, enum FRAME_TYPE type, const int content_length, const Byte *content, const int8_t rssi);
int sendFrame(const int client, enum FRAME_TYPE type, const unsigned long length, char * packet, int8_t rssi);

int getSSIDList(const int client);
int messageProceed(enum MESSAGE_TYPE type, char* contetn, int content_length );


#endif //YINMEE_SEND_FRAME_H
