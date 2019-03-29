//
// Created by root on 18-12-23.
//

#ifndef LURE_COMMON_H
#define LURE_COMMON_H

int ifFakeMAC(unsigned char *mac);
int changeFrame(char *frame, char* old_frame, char *ssid, int new_ssid_length, int old_ssid_len, int old_frame_len, char* des_mac);
int changeFrameSrcAddr(char* frame, int src_arrd_index, char* new_src_addr);


#endif //LURE_COMMON_H
