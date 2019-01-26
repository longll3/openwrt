//
// Created by root on 19-1-8.
//

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>


#define MAXLINE 4096

#define TYPE_BYTE 4
#define LENGTH_BYTE 4

int test ()
{

//    test();
    int    listenfd, connfd;
    struct sockaddr_in     servaddr, clientaddr;
    unsigned char    buff[4096];
    int     n;

    if( (listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ){
        printf("create socket error: %s(errno: %d)\n",strerror(errno),errno);
        exit(0);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(30007);

    printf("port : %d\n", servaddr.sin_port);

    if( bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) == -1){
        printf("bind socket error: %s(errno: %d)\n",strerror(errno),errno);
        exit(0);
    }

    if( listen(listenfd, 10) == -1){
        printf("listen socket error: %s(errno: %d)\n",strerror(errno),errno);
        exit(0);
    }

    int client_addr_sz = sizeof(clientaddr);

    printf("======waiting for client's request======\n");

    connfd = accept(listenfd, (struct sockaddr*) &clientaddr, &client_addr_sz);
    if (connfd == -1) {

//    if( (connfd = accept(listenfd, (struct sockaddr*)NULL, NULL)) == -1){
        printf("accept socket error: %s(errno: %d)",strerror(errno),errno);
//        continue;
    } else {
        printf ("accept a socket connection request, ip = %s\n", inet_ntoa(clientaddr.sin_addr));
    }

    while(1){

        n = recv(connfd, buff, TYPE_BYTE, 0);
        if (0 == n) {
            continue;
        }
        buff[n] = '\0';

        printf("recv msg from client: \n");

        int index = 0;
        int * content_type = &buff[0];
        int type = ntohl(*content_type);

        n = recv(connfd, buff, LENGTH_BYTE, 0);
        buff[n] = '\0';
        int * content_len = &(buff[0]);
        int len = ntohl(*content_len);

        n = recv(connfd, buff, len, 0);
        buff[n] = '\0';

        printf("the type is : %d, the length is : %d \n", type, len);

        int i = 0;
        for (i=0; i < len; i++) {
            printf("%02X ", buff[index]);
            index++;
        }
        printf("\n");




//        close(connfd);
    }

    close(listenfd);
}


/*
int main () {
    test();
    */
/*int a = 10;
    unsigned char *p = &a;
    int i = 0;
    for (; i < 4; i++) {
        printf("%02X ", *(p+i));
    }*//*



}*/
