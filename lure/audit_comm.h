//
// Created by root on 19-3-29.
//

#include <sys/types.h>
#include <netinet/in.h>
//#include "common/log.h"

#ifndef LURE_AUDIT_COMM_H
#define LURE_AUDIT_COMM_H

#define PROBE_RESP      \
	"\x50\x00\x00\x00\xCC\xCC\xCC\xCC\xCC\xCC\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\x00\x00"
#define RADIOTAP	\
	"\x00\x00\x26\x00\x2f\x40\x00\xa0\x20\x08\x00\xa0\x20\x08\x00\x00\x28\xc1\x04\x01\x02\x00\x00\x00\x00\x02\x6c\x09\xa0\x00\xda\x00\x00\x00\xd7\x00\xd6\x01"
#define BEACON	\
	"\x80\x00\x00\x00\xcc\xcc\xcc\xcc\xcc\xcc\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xb0\xd0"
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
#define BROADCAST (unsigned char*)"\xFF\xFF\xFF\xFF\xFF\xFF"



#define INDUCE_SSID_SIZE 200
#define HST_SSID_MAX_LEN	100
#define ATTACK_INTERVAL	    100000
#define ATTACK_CNT          1
#define FCS_LEN		4		//校验码长度

#define AUDIT_MAX_DATA_SIZE	4096		//帧最大长度

#define IEEE80211_MAX_SSID_LEN		32

#define MAC_ADDR_LEN		6   //MAC max length is 6, not includes '\0'
#define MAX_SSID_LEN		(IEEE80211_MAX_SSID_LEN+1)//last byte is '\0'
#define MAX_QQ_LEN			13  //QQ max length is 12, last one byte is '\0'
#define MAX_IMSI_LEN		16  //IMSI max length is 15, last one byte is '\0'
#define MAX_IMEI_LEN		16  //IMEI max length is 15, last one byte is '\0'
#define MAX_PHONE_LEN		12  //Cellphone number max length is 11, last one byte is '\0'
#define MAX_WEIXIN_LEN		32
#define MAX_TAOBAO_LEN		32
#define MAX_EMAIL_LEN		32
#define MAX_ACOUNT_LEN	    32
#define MAX_HISTORY_SSID	2
#define MAX_DIP_COUNT		30
#define MAX_SPORT_COUNT	MAX_DIP_COUNT
#define MAX_DPORT_COUNT	MAX_DIP_COUNT
#define MAX_VIRTUAL_SSID_SIZE 100
#define MAX_AP_SIZE 100
#define MAX_ASSOCIATED_EP_SIZE 256

/**
 * ---------------------------------------------------
 * @author longll
 */

enum
{
    BEACON_FRAME = 1,
    PROBE_RESP_FRAME,
};

struct ssid_list_from_server_s {
    char induced_ssid[MAX_SSID_LEN];//伪造的ssid
    int encrypt;//标志是否是加密的ssid, 0=non-encrypt, 1=encrypt, 2=unknown

};
typedef struct ssid_list_from_server_s ssid_list_from_server_t;

struct SSID_List_From_Server {
    int length;
    ssid_list_from_server_t *element[INDUCE_SSID_SIZE];
};


struct counterfeit_ssid_s
{
    char induced_ssid[MAX_SSID_LEN];//伪造的ssid
    uint8_t induced_mac[MAC_ADDR_LEN];//伪造ssid对应的mac地址
    int encrypt;//标志是否是加密的ssid, 0=non-encrypt, 1=encrypt, 2=unknown
    int hit;
    int radiate;//标志该ssid是否已虚拟出来
    time_t radiate_time;//该ssid虚拟出来时的时间
};
typedef struct counterfeit_ssid_s counterfeit_ssid_t;

struct Counterfeit_SSID_List{
    int length;
    counterfeit_ssid_t *element[INDUCE_SSID_SIZE];
};
extern unsigned char ap_mac[7];

extern struct SSID_List_From_Server ssid_list_from_server;
//用于虚拟深度ssid的结构体
extern struct Counterfeit_SSID_List counterfeit_ssid_list;

int pad_packet(char *ssid, int ssid_len, unsigned char *s_mac, unsigned char *d_mac,
               int frame_type, int encrytion_mode, int channel, char *packet, int packet_size);
int send_deeply_induced_ssid();

int fakeMac_raw(unsigned char *mac);


#endif //LURE_AUDIT_COMM_H
