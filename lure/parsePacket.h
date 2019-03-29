//
// Created by longll on 18-12-8.
//

#ifndef LURE_PARSEPACKET_H
#define LURE_PARSEPACKET_H

#include "ieee80211.h"
#include "make_packet.h"
#include "radiotap_parser.h"

#define MAC_ADDR_LEN 6
#define MAX_SSID_LEN		(IEEE80211_MAX_SSID_LEN+1)//last byte is '\0' 32+1



#include <stdio.h>
#include <string.h>


#define le16_to_cpu __le16_to_cpu

int parseRadiotap(const unsigned char* pData, int data_len);
int IEEE80211Parser(const unsigned char* pData, int data_len, int index);
int parseMgmtFrame(const unsigned char* fm_u_char, const int data_len, int index);
int parseSTProbereqFrame(const unsigned char* fm_u_char, const int data_len, const int index);

#endif //LURE_PARSEPACKET_H
