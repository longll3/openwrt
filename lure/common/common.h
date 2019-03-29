//
// Created by root on 18-12-23.
//

#ifndef LURE_COMMON_H
#define LURE_COMMON_H


#define GPS_DATA_PRINT 0

#define le16_to_cpu __le16_to_cpu
#define le32_to_cpu __le32_to_cpu
#define be16_to_cpu __be16_to_cpu
#define be32_to_cpu __be32_to_cpu

#define cpu_to_le16 __cpu_to_le16
#define cpu_to_le32 __cpu_to_le32
#define cpu_to_be16 __cpu_to_be16
#define cpu_to_be32 __cpu_to_be32


int ifFakeMAC(unsigned char *mac);
int changeFrame(char *frame, char* old_frame, char *ssid, int new_ssid_length, int old_ssid_len, int old_frame_len, char* des_mac);
int changeFrameSrcAddr(char* frame, int src_arrd_index, char* new_src_addr);


#endif //LURE_COMMON_H
