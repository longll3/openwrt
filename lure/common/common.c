//
// Created by root on 18-12-23.
//

#include "common.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

extern unsigned char* frame_to_be_send;

extern int ssid_begin_index; // ssid starts from this index included
extern int des_mac_begin_index; // total lenght of transmit mac and source mac should be 12

int ifFakeMAC(unsigned char *mac) {
    /*简单的说对于MAC地址 12 : 34 : 56 : 78 : 9A : BC  , 仅仅只需要看看第一个字节(12)的最后两个比特, 是否为10, 为10大部分情况下都为随机地址(除了一些特殊用途),
    所以对于第二个数是2, 6, A, E , 可以判断他为随机地址*/
    unsigned char c = (unsigned char)((mac[0] << 6));

    printf("%02X\n", c);

    int *a = (int *)mac;
    if (c == 0x80 || 0 == (*a)){
        return 1;
    }

    return 0;
}


int changeFrameSrcAddr(char* frame, int src_arrd_index, char* new_src_addr) {
    int i = 0, j = 0;
    for (i = src_arrd_index; j < 6; j++, i++) {
        frame[i] = new_src_addr[j];
    }
    for (j=0; j < 6; j++, i++) {
        frame[i] = new_src_addr[j];
    }
}

/**
 * @author longll
 * @return len of new frame
 */
int changeFrame(char *frame, char* old_frame, char *ssid, int new_ssid_length, int old_ssid_len, int old_frame_len, char* des_mac) {
//    unsigned char fram_bck[256] = {0};
//    memcpy(fram_bck, old_frame, old_frame_len);
    memcpy(frame, old_frame, old_frame_len);

    int index_old = 0;
    int i = 0, j=0;

    for (i=0, j = des_mac_begin_index; i < 6; i++) {
        frame[j++] = des_mac[i];
    }

    frame[ssid_begin_index-1] = new_ssid_length&0xff;

    for (i = 0, j = ssid_begin_index; i < new_ssid_length; i++, j++) {
        frame[j] = ssid[i];
    }

    for (i = ssid_begin_index+old_ssid_len; i < old_frame_len; i++, j++) {
        frame[j] = old_frame[i];
    }

    return j;


}