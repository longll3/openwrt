#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include "audit_comm.h"
#include "common/send_frame.h"


//虚拟ssid的ap mac的起始值，然后对于之后的每个ssid的mac都增1表示
static uint8_t tmp_induce_mac[MAC_ADDR_LEN] = {0xC8, 0xEE, 0xA6, 0x1E, 0x1A, 0x01};

unsigned char recvData[AUDIT_MAX_DATA_SIZE] = {0};

unsigned char audit_ap_mac[MAC_ADDR_LEN] = {0};

unsigned char ap_mac[7] = {0x7c, 0xdd, 0x90, 0xf6, 0xcd, 0x90};

struct Counterfeit_SSID_List counterfeit_ssid_list;

struct SSID_List_From_Server ssid_list_from_server;

/**
 * ---------------------------------------------------
 * @author longll
 */

struct SSID_List_From_Server ssid_list_from_server;

//#define SEND_DEEPLY_BEACON 0
#define READ_DEFAULT_SSID_LIST 1
//#define SEND_STATIONS_HIS_SSID_PROBERESPONSE 0
//#define SEND_PROBE_RESPONSE_FROM_SSIDLIST_FROM_SERVER 1


// ---------------------------------------------------



//用于同步虚拟深度ssid列表的操作
pthread_mutex_t mutex_counterfeit_list;

pthread_mutex_t mutex_ssid_list_from_server;

//检测是否为空数据帧
//输入参数为数据的长度
int checkData(int data_len)
{
	if (data_len <= FCS_LEN)
		return 0;

	return 1;
}

/**
 *
 * @param mac
 * @return 1 if the mac is a random mad
 */
int fakeMac_raw(unsigned char *mac)
{
    /*简单的说对于MAC地址 12 : 34 : 56 : 78 : 9A : BC  , 仅仅只需要看看第一个字节(12)的最后两个比特, 是否为10, 为10大部分情况下都为随机地址(除了一些特殊用途),
    所以对于第二个数是2, 6, A, E , 可以判断他为随机地址*/
	unsigned char c = (unsigned char)((mac[0] << 6));
	int *a = (int *)mac;
	if (c == 0x80 || 0 == (*a)){
        return 1;
	}

	return 0;
}

int pad_packet(char *ssid, int ssid_len, unsigned char *s_mac, unsigned char *d_mac,
               int frame_type, int encrytion_mode, int channel, char *packet, int packet_size)
{
	int len;
	static int sequence_num = 0;
	memset(packet, 0, packet_size);

	//RADIOTAP
	memcpy(packet, RADIOTAP, sizeof(RADIOTAP)-1);
	len = sizeof(RADIOTAP)-1;

	sequence_num++;
	if(sequence_num > 4095)
	{
		sequence_num = 0;
	}
	//BEACON
	if(frame_type == BEACON_FRAME)
	{
		memcpy(packet + len, BEACON, sizeof(BEACON)-1);
		memcpy(packet + len + 4, d_mac, 6);
		memcpy(packet + len + 10, s_mac, 6);
		memcpy(packet + len + 16, s_mac, 6);
		len = len + sizeof(BEACON)-1;
		packet[len - 2] = (char) (sequence_num << 4 & 0xf0);
		packet[len - 1] = (char) (sequence_num >> 4 & 0xff);
	}
	//PROBE_RESP
	if(frame_type == PROBE_RESP_FRAME)
	{
		memcpy(packet + len, PROBE_RESP, sizeof(PROBE_RESP)-1);
		memcpy(packet + len + 4, d_mac, 6);
		memcpy(packet + len + 10, s_mac, 6);
		memcpy(packet + len + 16, s_mac, 6);
		len = len + sizeof(PROBE_RESP)-1;
		packet[len - 2] = (char) (sequence_num << 4 & 0xf0);
		packet[len - 1] = (char) (sequence_num >> 4 & 0xff);
	}
	//FP
	memcpy(packet + len, FP, sizeof(FP)-1);
	len = len + sizeof(FP)-1;
	if(encrytion_mode == 1)
	{
		packet[len - 2] = 0x31;
		packet[len - 1] = 0x04;
	}
	//SSID
	packet[len] = 0x00;//ESSID Tag Number
	packet[len + 1] = ssid_len; //ESSID Tag Length
	memcpy(packet + len + 2, ssid, ssid_len);
	len = len + 2 + ssid_len;
	//RATES
	memcpy(packet + len, RATES, sizeof(RATES)-1);
	len = len + sizeof(RATES)-1;
	//CHANNEL
	packet[len] = 0x03;
	packet[len + 1] = 0x01;
	packet[len + 2] = (char)(channel);
	len = len + 3;
	//TIM
	if(frame_type == BEACON_FRAME)
	{
		memcpy(packet + len, TIM, sizeof(TIM)-1);
		len = len + sizeof(TIM)-1;
	}
	//CI
	memcpy(packet + len, CI, sizeof(CI)-1);
	len = len + sizeof(CI)-1;
	//ERP
	memcpy(packet + len, ERP, sizeof(ERP)-1);
	len = len + sizeof(ERP)-1;
	//if need to encrypt
	if(encrytion_mode == 1)
	{
		//RSN
		memcpy(packet + len, RSN, sizeof(RSN)-1);
		len = len + sizeof(RSN)-1;
	}
	//HTC
	memcpy(packet+len, HTC, sizeof(HTC)-1);
	len = len + sizeof(HTC)-1;
	//HTI
	memcpy(packet+len, HTI, sizeof(HTI)-1);
	len = len + sizeof(HTI)-1;
	//EC
	memcpy(packet+len, EC, sizeof(EC)-1);
	len = len + sizeof(EC)-1;
	//VSM
	memcpy(packet+len, VSM, sizeof(VSM)-1);
	len = len + sizeof(VSM)-1;

	return len;
}

int send_deeply_induced_ssid()
{
	static time_t last_read_time = 0;
	int hst_ssid_cnt =0 ;
	int len;
	int i, k, n;
	int send_result = 0;

	static int getSSID = 0;



    unsigned int *mac_t;
    unsigned char *ap_mac;
    ap_mac = tmp_induce_mac;
    mac_t = (unsigned int *)(ap_mac + 2);

//从本地文件中读取默认要发送的的ssid
#ifdef READ_DEFAULT_SSID_LIST

    int time_diff = time(NULL) - last_read_time;  // 返回自纪元 Epoch（1970-01-01 00:00:00 UTC）起经过的时间，以秒为单位
    if(time_diff >= 600){
//    if(time_diff >= 1800){
        FILE *fp_free = NULL;
        FILE *fp_encrypt = NULL;
        char ssid_tmp[MAX_SSID_LEN];
        //读取免费ssid
        for(i=0; i<3; i++){

            if((fp_free = fopen("/home/longll/free_ssid", "r")) == NULL){
                printf( "open file free_ssid error\n");
                return -1;
                continue;
            }

            memset(ssid_tmp, 0, MAX_SSID_LEN);
            pthread_mutex_lock(&mutex_counterfeit_list);
            counterfeit_ssid_list.length = 0;
            n = counterfeit_ssid_list.length;
            while(n < INDUCE_SSID_SIZE && !feof(fp_free) && fgets(ssid_tmp, 32, fp_free) != NULL){
                counterfeit_ssid_list.element[n] = (counterfeit_ssid_t *)calloc(sizeof(counterfeit_ssid_t), 1);
                if(!counterfeit_ssid_list.element[n]){
                    printf("Allocate memory error!");
                    break;
                }
                if(strchr(ssid_tmp, '\n')){
                    ssid_tmp[strlen(ssid_tmp)-1] = '\0';
                }
                if(0 == strlen(ssid_tmp)){
                    continue;
                }
                strcpy(counterfeit_ssid_list.element[n]->induced_ssid, ssid_tmp);
                strncpy(counterfeit_ssid_list.element[n]->induced_mac, ap_mac, 6);
                counterfeit_ssid_list.element[n]->encrypt = 0;
                counterfeit_ssid_list.element[n]->hit = 0;
                counterfeit_ssid_list.element[n]->radiate = 0;
                counterfeit_ssid_list.element[n]->radiate_time = 0;
                (*mac_t)++;
                counterfeit_ssid_list.length++;
                n = counterfeit_ssid_list.length;
                memset(ssid_tmp, 0, MAX_SSID_LEN);
            }
            pthread_mutex_unlock(&mutex_counterfeit_list);
            fclose(fp_free);
            break;
        }

        //读取加密ssid
        for(i=0; i<3; i++){
            if((fp_encrypt = fopen("/home/longll/encrypt_ssid", "r")) == NULL){
                printf( "open file encrypt_ssid error\n");
                return -1;
            }
            memset(ssid_tmp, 0, MAX_SSID_LEN);
            pthread_mutex_lock(&mutex_counterfeit_list);
            n = counterfeit_ssid_list.length;
            while(n < INDUCE_SSID_SIZE && !feof(fp_encrypt) && fgets(ssid_tmp, 32, fp_encrypt) != NULL){
                counterfeit_ssid_list.element[n] = (counterfeit_ssid_t *)calloc(sizeof(counterfeit_ssid_t), 1);
                if(!counterfeit_ssid_list.element[n]){
                    printf("Allocate memory error!");
                    break;
                }
                if(strchr(ssid_tmp, '\n')){
                    ssid_tmp[strlen(ssid_tmp)-1] = '\0';
                }
                if(0 == strlen(ssid_tmp)){
                    continue;
                }
                strcpy(counterfeit_ssid_list.element[n]->induced_ssid, ssid_tmp);
                strncpy(counterfeit_ssid_list.element[n]->induced_mac, ap_mac, 6);
                counterfeit_ssid_list.element[n]->encrypt = 1;
                counterfeit_ssid_list.element[n]->hit = 0;
                counterfeit_ssid_list.element[n]->radiate = 0;
                counterfeit_ssid_list.element[n]->radiate_time = 0;
                (*mac_t)++;
                counterfeit_ssid_list.length++;
                n = counterfeit_ssid_list.length;
                memset(ssid_tmp, 0, MAX_SSID_LEN);
            }
            pthread_mutex_unlock(&mutex_counterfeit_list);
            fclose(fp_encrypt);
            break;
        }
	
        last_read_time = time(NULL);
    }

	//从服务器获取ssid list
	if (getSSID == 0) {
		pthread_mutex_lock(&mutex_ssid_list_from_server);
		getSSIDList(socket_tcp);
		pthread_mutex_unlock(&mutex_ssid_list_from_server);
		getSSID = 1;
	}


#endif
    
// 给终端回复response，如果终端有历史ssid的话
#ifdef SEND_STATIONS_HIS_SSID_PROBERESPONSE

    //获取终端的历史ssid,首先需要判断是否已存在该ssid
    int is_exist_ssid = 0;
    pthread_mutex_lock(&mutex_station_list);
    pthread_mutex_lock(&mutex_counterfeit_list);
    k = counterfeit_ssid_list.length;
    for(n = 0; n < ep_station_list.length; n++){
        is_exist_ssid = 0;
        if(ep_station_list.element[n]->hst_ssid_valid == 1 && k < INDUCE_SSID_SIZE){
            for(i = k - 1; i >= 0; i--){
	//          if(counterfeit_ssid_list.element[i]->encrypt != 2){
	//          	//history ssid encrypted type is 2
	//              break;
	//          }
                if(0 == strcmp(ep_station_list.element[n]->hst_ssid[0], counterfeit_ssid_list.element[i]->induced_ssid)){
                    is_exist_ssid = 1;
                    if(0 == counterfeit_ssid_list.element[i]->encrypt && 0 == counterfeit_ssid_list.element[i]->hit){
                        //counterfeit_ssid_list.element[i]->hit = 1;
                        int ssid_len = strlen(counterfeit_ssid_list.element[i]->induced_ssid);
                        len = pad_packet(counterfeit_ssid_list.element[i]->induced_ssid, ssid_len,
                                         counterfeit_ssid_list.element[i]->induced_mac,
                                         ep_station_list.element[n]->mac,
                                        PROBE_RESP_FRAME, 0, attack_channel, packet, packet_size); //BEACON_FRAME PROBE_RESP_FRAME
                        int attack_cnt;
                        for(attack_cnt = 0; attack_cnt < ATTACK_CNT; attack_cnt++){
                            if(-1 == (send_result = sendto(sk, packet, len, 0, ssl_ptr, sizeof(struct sockaddr_ll)))){
                                printf("his0, send probe response to %02x-%02x-%02x-%02x-%02x-%02x error\n",
                                      ep_station_list.element[n]->mac[0],
                                      ep_station_list.element[n]->mac[1],
                                      ep_station_list.element[n]->mac[2],
                                      ep_station_list.element[n]->mac[3],
                                      ep_station_list.element[n]->mac[4],
                                      ep_station_list.element[n]->mac[5]);
                            }
                            usleep(ATTACK_INTERVAL);
                        }
                        printf("his0, send probe response to %02x-%02x-%02x-%02x-%02x-%02x,ssid=%s\n",
                                      ep_station_list.element[n]->mac[0],
                                      ep_station_list.element[n]->mac[1],
                                      ep_station_list.element[n]->mac[2],
                                      ep_station_list.element[n]->mac[3],
                                      ep_station_list.element[n]->mac[4],
                                      ep_station_list.element[n]->mac[5],
                                      ep_station_list.element[n]->hst_ssid[0]);
                        //radiateSSID(0);
                    }
                    break;
                }
            }

            /**
            if(is_exist_ssid || !fakeMac_raw(ep_station_list.element[n]->mac)){
                continue;
            }
            */

            if (is_exist_ssid) {
                continue;
            }

            counterfeit_ssid_list.element[k] = (counterfeit_ssid_t *)calloc(sizeof(counterfeit_ssid_t), 1);
            if(!counterfeit_ssid_list.element[k]){
                printf("Allocate memory error!");
                break;
            }
            memset(counterfeit_ssid_list.element[k]->induced_ssid, 0, MAX_SSID_LEN);
            memcpy(counterfeit_ssid_list.element[k]->induced_ssid, ep_station_list.element[n]->hst_ssid[0], 32);
            strncpy(counterfeit_ssid_list.element[k]->induced_mac, ap_mac, 6);
            counterfeit_ssid_list.element[k]->encrypt = 2;
            counterfeit_ssid_list.element[k]->hit = 0;
            counterfeit_ssid_list.element[k]->radiate = 0;
            counterfeit_ssid_list.element[k]->radiate_time = 0;
            (*mac_t)++;
            counterfeit_ssid_list.length++;
            k = counterfeit_ssid_list.length;
            if(ep_station_list.element[n]->hssid_len > 1 && k < INDUCE_SSID_SIZE){
                is_exist_ssid = 0;
                for(i = k - 1; i >= 0; i--){
//                    if(counterfeit_ssid_list.element[i]->encrypt != 2){
//                        //history ssid encrypted type is 2
//                        break;
//                    }
                    if(0 == strcmp(ep_station_list.element[n]->hst_ssid[1], counterfeit_ssid_list.element[i]->induced_ssid)){
                        is_exist_ssid = 1;
                        if(0 == counterfeit_ssid_list.element[i]->encrypt && 0 == counterfeit_ssid_list.element[i]->hit){
                            //counterfeit_ssid_list.element[i]->hit = 1;
                            int ssid_len = strlen(counterfeit_ssid_list.element[i]->induced_ssid);
                            len = pad_packet(counterfeit_ssid_list.element[i]->induced_ssid, ssid_len,
                                             counterfeit_ssid_list.element[i]->induced_mac,
                                             ep_station_list.element[n]->mac,
                                            PROBE_RESP_FRAME, 0, attack_channel, packet, packet_size); //BEACON_FRAME PROBE_RESP_FRAME
                            int attack_cnt;
                            for(attack_cnt = 0; attack_cnt < ATTACK_CNT; attack_cnt++){
                                if(-1 == (send_result = sendto(sk, packet, len, 0, ssl_ptr, sizeof(struct sockaddr_ll)))){
                                    printf("his1, send probe response to %02x-%02x-%02x-%02x-%02x-%02x error\n",
                                      ep_station_list.element[n]->mac[0],
                                      ep_station_list.element[n]->mac[1],
                                      ep_station_list.element[n]->mac[2],
                                      ep_station_list.element[n]->mac[3],
                                      ep_station_list.element[n]->mac[4],
                                      ep_station_list.element[n]->mac[5]);
                                }
                                usleep(ATTACK_INTERVAL);
                            }
                            printf("his1, send probe response to %02x-%02x-%02x-%02x-%02x-%02x,ssid=%s\n",
                                      ep_station_list.element[n]->mac[0],
                                      ep_station_list.element[n]->mac[1],
                                      ep_station_list.element[n]->mac[2],
                                      ep_station_list.element[n]->mac[3],
                                      ep_station_list.element[n]->mac[4],
                                      ep_station_list.element[n]->mac[5],
                                      ep_station_list.element[n]->hst_ssid[1]);
                            //radiateSSID(0);
                        }
                        break;
                    }
                }
                if(is_exist_ssid){
                    continue;
                }
                counterfeit_ssid_list.element[k] = (counterfeit_ssid_t *)calloc(sizeof(counterfeit_ssid_t), 1);
                if(!counterfeit_ssid_list.element[k]){
                    printf("Allocate memory error!");
                    break;
                }
                memset(counterfeit_ssid_list.element[k]->induced_ssid, 0, MAX_SSID_LEN);
                memcpy(counterfeit_ssid_list.element[k]->induced_ssid, ep_station_list.element[n]->hst_ssid[1], 32);
                strncpy(counterfeit_ssid_list.element[k]->induced_mac, ap_mac, 6);
                counterfeit_ssid_list.element[k]->encrypt = 2;
                counterfeit_ssid_list.element[k]->hit = 0;
                counterfeit_ssid_list.element[k]->radiate = 0;
                counterfeit_ssid_list.element[k]->radiate_time = 0;
                (*mac_t)++;
                counterfeit_ssid_list.length++;
                k = counterfeit_ssid_list.length;
            }
        }
    }
    pthread_mutex_unlock(&mutex_counterfeit_list);
    pthread_mutex_unlock(&mutex_station_list);
#endif


//发送深度虚拟的ssid, beacon
#ifdef SEND_DEEPLY_BEACON
    //发送深度虚拟的ssid,这里不用同步数据
    //pthread_mutex_lock(&mutex_counterfeit_list);
    for(i = 0; i < counterfeit_ssid_list.length; i++)
    {
        if(!counterfeit_ssid_list.element[i]->encrypt){
            len = pad_packet(counterfeit_ssid_list.element[i]->induced_ssid, strlen(counterfeit_ssid_list.element[i]->induced_ssid), counterfeit_ssid_list.element[i]->induced_mac,
                             BROADCAST, BEACON_FRAME, 0, attack_channel, packet, packet_size);
        }
        else if(1 == counterfeit_ssid_list.element[i]->encrypt){
            len = pad_packet(counterfeit_ssid_list.element[i]->induced_ssid, strlen(counterfeit_ssid_list.element[i]->induced_ssid), counterfeit_ssid_list.element[i]->induced_mac,
                             BROADCAST, BEACON_FRAME, 1, attack_channel, packet, packet_size);
        }
        else if(2 == counterfeit_ssid_list.element[i]->encrypt){
            len = pad_packet(counterfeit_ssid_list.element[i]->induced_ssid, strlen(counterfeit_ssid_list.element[i]->induced_ssid), counterfeit_ssid_list.element[i]->induced_mac,
                             BROADCAST, BEACON_FRAME, 0, attack_channel, packet, packet_size);
            for(k = 0; k < 3; k++)
            {
                if(-1 == (send_result = sendto(sk, packet, len, 0, ssl_ptr, sizeof(struct sockaddr_ll))))
                {
                    //pthread_mutex_unlock(&mutex_counterfeit_list);
                    printf("send_deeply_induced_ssid error occurred:%s\n", strerror(errno));
                    return -1;
                }
                usleep(ATTACK_INTERVAL);
            }

            len = pad_packet(counterfeit_ssid_list.element[i]->induced_ssid, strlen(counterfeit_ssid_list.element[i]->induced_ssid), counterfeit_ssid_list.element[i]->induced_mac,
                             BROADCAST, BEACON_FRAME, 1, attack_channel, packet, packet_size);
        }
        for(k = 0; k < 3; k++)
        {
            if(-1 == (send_result = sendto(sk, packet, len, 0, ssl_ptr, sizeof(struct sockaddr_ll))))
            {
                //pthread_mutex_unlock(&mutex_counterfeit_list);
                printf("send_deeply_induced_ssid error occurred:%s\n", strerror(errno));
                return -1;
            }
            usleep(ATTACK_INTERVAL);
        }
        /*printf("the ssid mac:%02x-%02x-%02x-%02x-%02x-%02x, ssid:%s\n",
                 counterfeit_ssid_list.element[i]->induced_mac[0],counterfeit_ssid_list.element[i]->induced_mac[1],
                 counterfeit_ssid_list.element[i]->induced_mac[2],counterfeit_ssid_list.element[i]->induced_mac[3],
                 counterfeit_ssid_list.element[i]->induced_mac[4],counterfeit_ssid_list.element[i]->induced_mac[5],
                 counterfeit_ssid_list.element[i]->induced_ssid);*/
    }
    //pthread_mutex_unlock(&mutex_counterfeit_list);

#endif

/**---------------------------------------------------------------------------------------------------------------------
 * @author longll
 */
//把从服务器接受的ssid们回复给所检测到的终端
#ifdef SEND_PROBE_RESPONSE_FROM_SSIDLIST_FROM_SERVER

	pthread_mutex_lock(&mutex_station_list); // synchronize

    for (n = 0; n < ep_station_list.length; n++) {

		for (k = 0; k < ssid_list_from_server.length; k++) {

			int ssid_len = strlen(ssid_list_from_server.element[k]->induced_ssid);

			if (ssid_list_from_server.element[k]->encrypt == 2) {
				//加密方式为 未知

				//先发送加密的
				len = pad_packet(ssid_list_from_server.element[k]->induced_ssid, ssid_len, ap_mac, ep_station_list.element[n]->mac,
								 BEACON_FRAME, 1, attack_channel, packet, packet_size);
				int attack_cnt = 0;
				for (attack_cnt = 0; attack_cnt < ATTACK_CNT; ++attack_cnt)
				{
					if (-1 == (send_result = sendto(sk, packet, len, 0, ssl_ptr, sizeof(struct sockaddr_ll)))) {
						printf("send beacon frame error , ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
							   ssid_list_from_server.element[k]->induced_ssid,
							   ep_station_list.element[n]->mac[0],
							   ep_station_list.element[n]->mac[1],
							   ep_station_list.element[n]->mac[2],
							   ep_station_list.element[n]->mac[3],
							   ep_station_list.element[n]->mac[4],
							   ep_station_list.element[n]->mac[5]);
					}
//					usleep(ATTACK_INTERVAL);
				}

				printf("sent beacon frame, ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
					   ssid_list_from_server.element[k]->induced_ssid,
					   ep_station_list.element[n]->mac[0],
					   ep_station_list.element[n]->mac[1],
					   ep_station_list.element[n]->mac[2],
					   ep_station_list.element[n]->mac[3],
					   ep_station_list.element[n]->mac[4],
					   ep_station_list.element[n]->mac[5]);

				//再发送不加密的
				len = pad_packet(ssid_list_from_server.element[k]->induced_ssid, ssid_len, ap_mac, ep_station_list.element[n]->mac,
								 BEACON_FRAME, 0, attack_channel, packet, packet_size);

				for (attack_cnt = 0; attack_cnt < ATTACK_CNT; ++attack_cnt)
				{
					if (-1 == (send_result = sendto(sk, packet, len, 0, ssl_ptr, sizeof(struct sockaddr_ll)))) {
						printf("send beacon frame error , ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
							   ssid_list_from_server.element[k]->induced_ssid,
							   ep_station_list.element[n]->mac[0],
							   ep_station_list.element[n]->mac[1],
							   ep_station_list.element[n]->mac[2],
							   ep_station_list.element[n]->mac[3],
							   ep_station_list.element[n]->mac[4],
							   ep_station_list.element[n]->mac[5]);
					}
					usleep(ATTACK_INTERVAL);
				}

				printf("sent beacon frame, ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
					   ssid_list_from_server.element[k]->induced_ssid,
					   ep_station_list.element[n]->mac[0],
					   ep_station_list.element[n]->mac[1],
					   ep_station_list.element[n]->mac[2],
					   ep_station_list.element[n]->mac[3],
					   ep_station_list.element[n]->mac[4],
					   ep_station_list.element[n]->mac[5]);



			} else if (ssid_list_from_server.element[k]->encrypt == 1) {
				//加密方式为 加密
				len = pad_packet(ssid_list_from_server.element[k]->induced_ssid, ssid_len, ap_mac, ep_station_list.element[n]->mac,
								 BEACON_FRAME, 1, attack_channel, packet, packet_size);
				int attack_cnt = 0;
				for (attack_cnt = 0; attack_cnt < ATTACK_CNT; ++attack_cnt)
				{
					if (-1 == (send_result = sendto(sk, packet, len, 0, ssl_ptr, sizeof(struct sockaddr_ll)))) {
						printf("send beacon frame error , ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
							   ssid_list_from_server.element[k]->induced_ssid,
							   ep_station_list.element[n]->mac[0],
							   ep_station_list.element[n]->mac[1],
							   ep_station_list.element[n]->mac[2],
							   ep_station_list.element[n]->mac[3],
							   ep_station_list.element[n]->mac[4],
							   ep_station_list.element[n]->mac[5]);
					}
//					usleep(ATTACK_INTERVAL);
				}

				printf("sent beacon frame, ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
					   ssid_list_from_server.element[k]->induced_ssid,
					   ep_station_list.element[n]->mac[0],
					   ep_station_list.element[n]->mac[1],
					   ep_station_list.element[n]->mac[2],
					   ep_station_list.element[n]->mac[3],
					   ep_station_list.element[n]->mac[4],
					   ep_station_list.element[n]->mac[5]);



			} else if (ssid_list_from_server.element[k]->encrypt == 0) {
				//加密方式为 不加密 free

				len = pad_packet(ssid_list_from_server.element[k]->induced_ssid, ssid_len, ap_mac, ep_station_list.element[n]->mac,
								 BEACON_FRAME, 0, attack_channel, packet, packet_size);
				int attack_cnt = 0;
				for (attack_cnt = 0; attack_cnt < ATTACK_CNT; ++attack_cnt)
				{
					if (-1 == (send_result = sendto(sk, packet, len, 0, ssl_ptr, sizeof(struct sockaddr_ll)))) {
						printf("send beacon frame error , ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
							   ssid_list_from_server.element[k]->induced_ssid,
							   ep_station_list.element[n]->mac[0],
							   ep_station_list.element[n]->mac[1],
							   ep_station_list.element[n]->mac[2],
							   ep_station_list.element[n]->mac[3],
							   ep_station_list.element[n]->mac[4],
							   ep_station_list.element[n]->mac[5]);
					}
					usleep(ATTACK_INTERVAL);
				}

				printf("sent beacon frame, ssid = %s\n, ep_mac=%02x-%02x-%02x-%02x-%02x-%02x",
					   ssid_list_from_server.element[k]->induced_ssid,
					   ep_station_list.element[n]->mac[0],
					   ep_station_list.element[n]->mac[1],
					   ep_station_list.element[n]->mac[2],
					   ep_station_list.element[n]->mac[3],
					   ep_station_list.element[n]->mac[4],
					   ep_station_list.element[n]->mac[5]);

			}
		}
    }
	pthread_mutex_unlock(&mutex_station_list);

	
#endif
//----------------------------------------------------------------------------------------------------------------------

    return 0;
}

