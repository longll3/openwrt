//
// Created by longll on 18-12-8.
//

#include <printf.h>
#include "sendPacket.h"
#include "parsePacket.h"
#include "common/common.h"

//½âÎöradiotapÖ¡
int parseRadiotap(const unsigned char* pData, int data_len)
{
//    printf("parse radiotap\n");

    int header_len = 0;
    int rt_index = 0;

    struct ieee80211_radiotap_header * rt_header =
            (struct ieee80211_radiotap_header *) pData;
    struct ieee80211_radiotap_iterator rt_iterator;

    header_len = (rt_header->it_len);

    if (header_len > data_len) {

        printf("radiotap length exceeed packet caplen\n");
        return -1;
    }


    return header_len;
}

//½âÎöieee80211Ö¡
int IEEE80211Parser(const unsigned char* pData, int data_len)
{
//    printf("parse ieee80211\n");

    int header_len = 0;

    struct ieee80211_hdr* fm_header =
            (struct ieee80211_hdr*) pData;

    //¸ù¾ÝÖ¡ÀàÐÍ½øÐÐ´¦Àí
    if ( 1 == ieee80211_is_mgmt(fm_header->frame_control) )
    {
        //¹ÜÀíÖ¡
        printf("it is a management frame\n");
        header_len = parseMgmtFrame(pData, data_len);

    }else if ( 1 == ieee80211_is_ctl(fm_header->frame_control) )
    {
        //¿ØÖÆÖ¡
        header_len = -1;
//        header_len = parseCtlFrame(pData, data_len);
    }else if ( 1 == ieee80211_is_data(fm_header->frame_control) )
    {
        header_len = -1;
//        header_len = parseDataFrame(pData, data_len);
    }else
    {
        /*
            ¶ÔÒ»ÏÂ¶¨Òå×ö´óÐ¡¶Ë×ª»»£¬¿ÉÒÔ»ñµÃÊý¾Ý°üÀàÐÍ
            #define IEEE80211_FTYPE_MGMT		0x0000
            #define IEEE80211_FTYPE_CTL		0x0004
            #define IEEE80211_FTYPE_DATA		0x0008
            #define IEEE80211_FTYPE_EXT		0x000c
        */
//        g_stru_frameCnt.unknownFrameCnt++;
//        if (LOG_DL_RADIO)
//            log_error("get error FTYPE(%d)\n",(fm_header->frame_control&cpu_to_le16(IEEE80211_FCTL_FTYPE)));
        header_len = -1;
    }

    return header_len;
}

int parseMgmtFrame(const unsigned char* fm_u_char, const int data_len)
{
    /*
        Çø·Ö¹ÜÀíÖ¡×ÓÀàÐÍ²¢·ÖÀà´¦Àí
        Association request
        Association response
        Reassociation request
        Reassociation response
        Probe request
        Probe response
        Beacon
        Announcement traffic indication message (ATIM)
        Disassociation
        Authentication
        Deauthentication
        Action
    */

//    printf("parse management frame\n");

    int header_len = 0;
    struct ieee80211_hdr* fm_header = (struct ieee80211_hdr*) fm_u_char;


    /*
        Çø·Ö¹ÜÀíÖ¡×ÓÀàÐÍ²¢·ÖÀà´¦Àí
    */

    if(1 == ieee80211_is_probe_req(fm_header->frame_control))
    {
//        printf("it is a probe request frame\n");
        //Probe request(Ì½²â/Ì½ÕëÇëÇóÖ¡)
        header_len = parseSTProbereqFrame(fm_u_char, data_len);
    }
    else
    {
        header_len = -1;
    }

    return header_len;
}

char* fake_ssids[4];

char * fake_ssid_1;
char * fake_ssid_2;
char * fake_ssid_3;
char * fake_ssid_4;


extern int frame_len_3d3f;
extern int frame_len_45e1;
extern int frame_len_to_be_send;

unsigned char frame_3d3f[256];
unsigned char frame_45e1[256];
unsigned char frame_to_be_send[256];

extern int packet_size;
extern unsigned char packet[256];

unsigned char *s_mac;


int parseSTProbereqFrame(const unsigned char* fm_u_char, const int data_len) {
    printf("parse probe requesr frame\n");

    int i = 0;
    int header_len = 0;
    int err_ssidLen = 0;
    unsigned char tmp_mac[MAC_ADDR_LEN] = {0};

    struct ieee80211_hdr * fm_header =
            (struct ieee80211_hdr *) fm_u_char;

    struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *) fm_u_char;
    struct ieee80211_ie *ie = (struct ieee80211_ie *) mgmt->u.probe_req.variable;
    int offset = 24, is_history = 0, ssid_len = 0;
    uint8_t ssid[MAX_SSID_LEN] = {0};


    //±£´æmacµØÖ·
    memcpy(tmp_mac, ieee80211_get_SA(fm_header), MAC_ADDR_LEN);

    //±éÀúÐÅÏ¢ÔªËØ²¿·Ö
    //»ñÈ¡ÀúÊ·ssid
    while(data_len - offset > FCS_LEN) { //frame check sequence length=4,Ã¿Ö¡µÄ×îºó4¸ö×Ö½ÚÊÇÓÃÀ´Ð£ÑéµÄ
        switch (ie->id){
            case WLAN_EID_SSID:
                ssid_len = (int)ie->len; // Convert the type of ie->len from unsigned int with 8 bits to int
                if (ssid_len > IEEE80211_MAX_SSID_LEN) return -1;
                if(ssid_len > 0){
                    memcpy(ssid, (char *) ie->data, ssid_len);
                    ssid[ssid_len] = '\0';
                    is_history = 1;
                }
                break;
            case WLAN_EID_VENDOR_SPECIFIC:
                break;
                //case CURRENT_CHANNEL:break;
        }

        offset += ie->len + 1 + 1;
        ie = (struct ieee80211_ie *) ((uint8_t *) ie  + ie->len + 1 + 1 );
    }

    //Ã»ÓÐssid£¬ÔòÊÇÉ¨ÃèÖ¡£¬·¢ËÍ´øÓÐssidµÄÌ½²âÏìÓ¦Ö¡
    if (!is_history) {
        //send probe response with different ssid
        printf("src mac: %02X-%02X-%02X-%02X-%02X-%02X\n", tmp_mac[0], tmp_mac[1], tmp_mac[2], tmp_mac[3], tmp_mac[4], tmp_mac[5]);

        if (!ifFakeMAC(tmp_mac)) {
            //if it is not a random mac address
            return -1;
        }

        uint8_t mate7_1[6] = {0xb4, 0x30, 0x52, 0xfd, 0xbb, 0xf5};
        unsigned char *d_mac = calloc(1, sizeof(unsigned char));
        memcpy(d_mac, mate7_1, 6);

        int fake_ssid_len = strlen(ssid);


        int i = 0, j = 0;
        for (i = 0; i < 2; i++) {
            printf("send probe response\n");
            prepareBeaconORProbeResponseFrame(tmp_mac, s_mac, fake_ssids[i], strlen(fake_ssids[i]), PROBE_RESP_FRAME, 1);
//          prepareBeaconORProbeResponseFrame(d_mac, s_mac, fake_ssids[i], strlen(fake_ssids[i]), PROBE_RESP_FRAME, 1);
            sendPcakage(1, packet, packet_size);
        }
        prepareBeaconORProbeResponseFrame(tmp_mac, s_mac, fake_ssids[i++], strlen(fake_ssids[2]), PROBE_RESP_FRAME, 0);
        sendPcakage(1, packet, packet_size);
        prepareBeaconORProbeResponseFrame(tmp_mac, s_mac, fake_ssids[i], strlen(fake_ssids[3]), PROBE_RESP_FRAME, 0);
        sendPcakage(1, packet, packet_size);

        /*//send probe response came from real AP
        sendPcakage(1, frame_3d3f, frame_len_3d3f);
        sendPcakage(1, frame_45e1, frame_len_45e1);*/

        printf("sent probe request frame\n");
    } else {

        printf("mac=%02x-%02x-%02x-%02x-%02x-%02x, ssid = %s\n", tmp_mac[0], tmp_mac[1], tmp_mac[2], tmp_mac[3], tmp_mac[4], tmp_mac[5], ssid);
    }

//ether src  b4:30:52:fd:bb:f5 or ether src 7c-dd-90-f6-cd-90
}