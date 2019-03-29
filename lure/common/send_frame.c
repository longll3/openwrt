//
// Created by root on 1/26/19.
//

#include <zconf.h>
#include <memory.h>
#include <errno.h>
#include "send_frame.h"
#include "../ieee80211.h"


//
// Created by root on 19-1-8.
//



#include "msg.h"
#include "send_frame.h"

char newhost[64] = {0};
char new_tcp_port[6] = {0};
int socket_tcp = -1;
int CREAT_SOCKET = 0;

int tcp_socket_down = 0;

int sk;

#define TIMEOUT 30  /**< wait for recreating socket */
#define BLOCK_TIMEOUT 60 /**< socket block time */

//#define UPLOAD_DEBUG 1

uint32_t PORT = 30007;
char *cserver = "192.168.113.1";
//char *cserver = "172.20.10.4";

#define le16_to_cpu __le16_to_cpu
#define le32_to_cpu __le32_to_cpu
#define be16_to_cpu __be16_to_cpu
#define be32_to_cpu __be32_to_cpu

#define cpu_to_le16 __cpu_to_le16
#define cpu_to_le32 __cpu_to_le32
#define cpu_to_be16 __cpu_to_be16
#define cpu_to_be32 __cpu_to_be32

int createSocket() {

    int new_fd;
    struct sockaddr_in dest_addr;
    char buf[1601];

    socket_tcp = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_tcp==-1){
        printf("socket连接失败，代码 %d", errno);
    }
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port=htons(PORT);
    dest_addr.sin_addr.s_addr=inet_addr(cserver);
    bzero(&(dest_addr.sin_zero), 8);

    if(connect(socket_tcp, (struct sockaddr*)&dest_addr, sizeof(struct sockaddr))==-1){
        printf("连接到后台服务器失败（一般是智障没启动后台或者后台端口改了造成Connection refused（错误代码111））实际错误代码：%d\n", errno);
    }else{
        printf("连接到后台服务器成功\n");
    }


    return 1;

}

int formatData(TELEGRAM **telegram, enum FRAME_TYPE type, const int content_length, const Byte *content, const int8_t rssi) {

    if (type == PROBE_REQUEST_FRAME) {

        int total_size = sizeof(TELEGRAM) + content_length + 1; // 1 byte for rssi
        (*telegram) = (TELEGRAM *)malloc(total_size);
        if(NULL == (*telegram)){
            printf("Memory assigned failed!");
            return -1;
        }
        memset(*telegram, 0, total_size);
        (*telegram)->datatype = type;
        (*telegram)->content_length = content_length + 1;
        memcpy((*telegram)->content, content, (*telegram)->content_length);
        memcpy((*telegram)->content+content_length, &rssi, 1);

    } else {
        int total_size = sizeof(TELEGRAM) + content_length;
        (*telegram) = (TELEGRAM *)malloc(total_size);
        if(NULL == (*telegram)){
            printf("Memory assigned failed!");
            return -1;
        }
        memset(*telegram, 0, total_size);
        (*telegram)->datatype = type;
        (*telegram)->content_length = content_length;
        memcpy((*telegram)->content, content, (*telegram)->content_length);
    }



    return 0;
}

int sendFrame(const int client, enum FRAME_TYPE type, const uLong length, char * packet, int8_t rssi) {
#ifdef UPLOAD_DEBUG
    printf("Begin to send_Frame. the socket_tcp = %d\n", socket_tcp);
#endif

    if (tcp_socket_down) {

        printf("tcp socket has been down, recreate socket connection\n");
        createSocket();
        tcp_socket_down = 0;
    }

    TELEGRAM *data_tele;
    unsigned char data_body[1024*64] = {0};
    int data_len = 0;
    int datatype = 0;

    if (-1 == formatData(&data_tele, type, length, (Byte *) packet, rssi)) {
        printf("Construct the data telegram failed!\n");
//        free(data_tele);
        return -1;
    }

    data_len = data_tele->content_length;
    datatype = data_tele->datatype;

    data_tele->datatype = cpu_to_be32(data_tele->datatype);
    data_tele->content_length = cpu_to_be32(data_tele->content_length);

#ifdef UPLOAD_DEBUG
    printf("data len is: %d, data type is: %d\n", data_len, datatype);
    printf("data len is: %d, data type is: %d\n", data_tele->content_length, data_tele->datatype);

    int i = 0;
    unsigned char *start = (unsigned char *)data_tele;
    for (i=0; i < sizeof(TELEGRAM) + data_len; i++) {
        printf("%02x ", *(start+i));

    }
    printf("\n");
#endif

    if (data_len > 1000 || sizeof(TELEGRAM) > 1000) {
        printf("message length is too long , data_len = %d, sizeof(TELEGRAM) = %d\n", data_len, sizeof(TELEGRAM));
        free(data_tele);
        return -1;
    }


    int sendNumber = send(client, (void *)data_tele, sizeof(TELEGRAM) + data_len, 0);
    if(-1 == sendNumber) {
//    if(-1 == send(client, data_body, data_len, 0)) {
        printf("sendFrame: send data error: %s, the data type is %d\n", strerror(errno), datatype);
        close(client);
        free(data_tele);
        tcp_socket_down = 1;
        return -1;
    } else {
        printf("send result: %d\n", sendNumber);
    }
    free(data_tele);

#ifdef UPLOAD_DEBUG
    printf("End to send_data_socket.\n");
#endif
    return 0;
}

/**
 * get ssid list which to be send
 * @param client: sokcet id
 * @return -1 : get info failed
 *          1 : success
 */
int getSSIDList(const int client) {
#ifdef UPLOAD_DEBUG
    log_debug("getSSIDList start");
#endif // UPLOAD_DEBUG
    char getorder_data[64] = {0};
    char command[PACKET_MAXLEN] = {0};
    int recvMsg_len;
    static unsigned int order_cnt = 0;

    if (client == -1) {
        printf("connection failed\n");
        createSocket();
    }

    int send = sendFrame(client, ASK_SSID, 1, "1", 0);
    if (send == -1) {
        printf("send ask ssid list error\n");
        return -1;
    }

    if(-1 == (recvMsg_len = recv(client, command, sizeof(command), 0))) {
        printf("upload : recv ssid list error : %d, %s, %s", errno, strerror(errno), command);
        if(11 == errno){
            //Resource temporarily unavailable, receive buffer has no nothing to read even timeout
            return 0;
        }
        close(client);
//        tcp_socket_close = 1;
        return -1;

    }else if(0 == recvMsg_len){
        printf("upload : recv ssid list error : %d, %s, %s", errno, strerror(errno), "network broken/interrupted");
        close(client);
//        tcp_socket_close = 1;
        return -1;
    }

    // print per 10 times
    if(order_cnt++ % 10 == 0){
        printf("recv_data order:%s", command);
    }

    //construct_order(command);

    /*»ñÈ¡ssidÐÅÏ¢´¦Àí*/
    int result = messageProceed(SSID_LIST, command, recvMsg_len);

#ifdef UPLOAD_DEBUG
    log_debug("getOrder end");
#endif // UPLOAD_DEBUG
    return result;
}

int messageProceed(enum MESSAGE_TYPE type, char* contetn, int content_length ) {
    if (type == SSID_LIST) {
        printf("recv message from server: %s\n", contetn);


    }
}

