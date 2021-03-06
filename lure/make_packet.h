//
// Created by longll on 18-4-23.
//

#ifndef LURE_MAKE_PACKET_H
#define LURE_MAKE_PACKET_H


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <zconf.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>

#define PROBE_RESPONSE_3D3F		\
"\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x9e\x09\xa0\x00\xd9\x01\x00\x00\x50\x00\x00\x00\x00\x24\xb2\xe2\xdc\xab\xe6\x9\x56\xe4\x23\xd3\xfe\x69\x56\xe4"	\
"\x23\xd3\xff\x09\xec\x47\xe2\xbd\x52\x60\x00\x00\x06\x40\x03\x10\x40\x00\xc7\x36\xd6\x17\x27\x46\x17\x02\xd3\x36\x43\x36\x60\x10\x88\x28\x48\xb9\x60\xc1\x21\x82\x40\x30\x10\xb0\x70\x65\x55\x32\x00\x10\xb1"	\
"\x2a\x01\x00\x32\x04\x30\x48\x60\x6c\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\xfa\xc0\x20\xc0\x03\xb0\x25\x10\x02\xd1\xae\xd1\x11\xbf\xff\xf0\x00\x00\x00\x00\x00\x00\x00\x00"	\
"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3d\x60\xb0\x01\x50\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\xf0\x80\x40\x00\x00\x00\x00\x00\x04\x0d\xd1\x80\x05\x0f\x20"	\
"\x01\x80\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00"

#define RADIOTAP	\
	"\x00\x00\x26\x00\x2f\x40\x00\xa0\x20\x08\x00\xa0\x20\x08\x00\x00\x28\xc1\x04\x01\x02\x00\x00\x00\x00\x02\x6c\x09\xa0\x00\xda\x00\x00\x00\xd7\x00\xd6\x01"
#define BEACON	\
	"\x80\x00\x00\x00\xcc\xcc\xcc\xcc\xcc\xcc\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xb0\xd0"
#define PROBE_RESP      \
	"\x50\x00\x00\x00\xCC\xCC\xCC\xCC\xCC\xCC\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\x00\x00"
#define FP		\
	"\x25\x25\x25\x25\x25\x00\x00\x00\x64\x00\x21\x04"
#define RATES	\
    "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"
#define TIM		\
	"\x05\x04\x01\x02\x00\x00"
#define CI      \
	"\x07\x06\x55\x53\x20\x01\x0b\x1e"
#define ERP      \
	"\x2a\x01\x00"
#define HTC      \
	"\x2d\x1a\xed\x11\x1b\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define HTI      \
	"\x3d\x16\x0b\x00\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define RSN      \
	"\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x0c\x00"
#define EC      \
	"\x7f\x08\x00\x00\x00\x00\x00\x00\x00\x40"
#define VSM      \
	"\xdd\x18\x00\x50\xf2\x02\x01\x01\x80\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00"

#define RTS \
    "\xb4\x00\xdc\x00\x48\xBF\x6B\xD0\x7A\x6E\x7c\xdd\x90\xf6\xcd\x90"
#define BROADCAST (unsigned char*)"\xFF\xFF\xFF\xFF\xFF\xFF"

#define DEAUTH_RT_HEAD \
    "\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x9e\x09\xa0\x00\xc4\x01\x00\x00"

#define DEAUTH_RD_INFO \
    "\xc0\x00\x3a\x01"

#define DEAUTH_DADDR \
    "\x24\x1F\xA0\x35\x32\x41"
//"\x24\x1f\xa0\x35\x32\x41"

#define DEAUTH__SADDR \
    "\xE4\x95\x6E\x41\x08\x4C"
//"\xe4\x95\x6e\x40\xf9\x2c"
//"\xca\xee\xa6\x1f\x65\xda"'


#define DEAUTH__BSSID \
    "\xE4\x95\x6E\x41\x08\x4C"

#define DEAUTH__FRAME_INFO \
    "\x40\x00\x07\x00"


#define HST_SSID_MAX_LEN	100


#define FCS_LEN		4		//校验码长度

#define AUDIT_MAX_DATA_SIZE	4096		//帧最大长度

//设备同时解析的最大数目
#define MAX_STATION_AMMOUNT	1500

//客户端白名单的最大数目
#define MAX_WHITE_LIST_AMMOUNT	1024

#define INDUCE_SSID_SIZE 200
#define EP_LABEL_SIZE 100

#define STATISTICS_SSID_SIZE 300
#define MAX_CHAR_EACH_LINE 1024



#define radiptapLength 18

enum
{
    BEACON_FRAME = 1,
    PROBE_RESP_FRAME,
    RTS_FRAME,
    CTS_FRAME
};

enum {
    RD_DIR_AP2EP = 1,
    RD_DIR_AP2AP,
    RD_DIR_EP2EP,
    RD_DIR_EP2AP
};

//协议类型
enum {
    PROTOCOL_TYPE_HTTP = 1,
    PROTOCOL_TYPE_WAP,
    PROTOCOL_TYPE_SMTP,
    PROTOCOL_TYPE_POP3,
    PROTOCOL_TYPE_IMAP,
    PROTOCOL_TYPE_NNTP,
    PROTOCOL_TYPE_FTP,
    PROTOCOL_TYPE_SFTP,
    PROTOCOL_TYPE_TELNET,
    PROTOCOL_TYPE_HTTPS,
    PROTOCOL_TYPE_RSTP,
    PROTOCOL_TYPE_MMS,
    PROTOCOL_TYPE_WEP,
    PROTOCOL_TYPE_WPA,
    PROTOCOL_TYPE_PPTP,
    PROTOCOL_TYPE_L2TP,
    PROTOCOL_TYPE_SOCKS,
    PROTOCOL_TYPE_COMPO,
    PROTOCOL_TYPE_CMSMTP,
    PROTOCOL_TYPE_PRIVATE = 91,
    PROTOCOL_TYPE_OTHER = 99
};


int pad_packet(char *ssid, int ssid_len, unsigned char *s_mac, unsigned char *d_mac,
               int frame_type, int encrytion_mode, int channel, char *packet, int packet_size);


int pad_rts_packet(int frame_type, unsigned char *s_mac, unsigned char *d_mac, int packet_size, char * packet);

int prepareBeaconORProbeResponseFrame(char* d_mac, char* s_mac, char* ssid, int ssid_len, int frame_type, int encryption_mode);


#endif //LURE_MAKE_PACKET_H
