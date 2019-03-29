
//#include <unistd.h>

#include <stdbool.h>
//#include "make_packet.h"
//#include "fakeFrameSend.h"
#include "parsePacket.h"
#include "sendPacket.h"
#include "common/common.h"
#include "common/send_frame.h"
#include "audit_comm.h"
#include <pcap.h>


u_char * rts_frame;
uint8_t frame[256];
int frame_len = 0;

int frame_len_3d3f = 0;
int frame_len_45e1 = 0;
int frame_len_to_be_send = 0;

int ssid_begin_index = 0; // ssid starts from this index included
int des_mac_begin_index = 0; // 

extern unsigned char frame_3d3f[256];
extern unsigned char frame_45e1[256];
extern unsigned char frame_to_be_send[256];

int packet_size;
unsigned char packet[256];

void handle_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

//    printf("get one packet\n");

    int data_len = pkthdr->caplen;
    int header_len = 0;
    if (NULL == packet || 0 == pkthdr->caplen)
    {
        printf("No data!\n");
        return;
    }

    //检测是否为空数据帧
    if (pkthdr->caplen <= FCS_LEN) {
        return;
    }

    //数据太长
    if (pkthdr->caplen > AUDIT_MAX_DATA_SIZE) {
        return;
    }

    //解析radiotap

    int8_t rssi = 0;
    int8_t* rssi_ptr = &rssi;
    int ret_len = parseRadiotap(packet, data_len, rssi_ptr);
    header_len += ret_len;

    //解析IEEE802.11帧
//    ret_len = IEEE80211Parser(packet + header_len, data_len - header_len);
    ret_len = IEEE80211Parser(packet, data_len, header_len, rssi);


//    printf("\n");

    frame_len = pkthdr->caplen;

    return;
}

void handle_probe_reponse_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    int i = 0;
    for (i = 0; i < pkthdr->caplen; i++) {
        printf("%02x-", packet[i]);
    }
    memcpy(frame, packet, pkthdr->caplen);
    frame_len = pkthdr->caplen;

    printf("\n");
}



//void prepareRTSFrame(char * d_mac, char * s_mac) {
//    packet_size = pad_rts_packet(RTS_FRAME, s_mac, d_mac, packet_size, &packet);
//}

void prepraePacket() {
    char * ssid = "probe1";
    int ssid_len = strlen(ssid);
    //7c:dd:90:f6:cd:90
//    uint8_t ap_mac[6] = {0xa4, 0x2b, 0x8c, 0x19, 0x32, 0x06};
    uint8_t ap_mac[6] = {0x7c, 0xdd, 0x90, 0xf6, 0xcd, 0x90};
    unsigned char *s_mac = calloc(1, sizeof(unsigned char));
    memcpy(s_mac, ap_mac, 6);
    uint8_t phone_mac[6] = {0x48, 0xBF, 0x6B, 0xD0, 0x7A, 0x6E};
    uint8_t phone7_2_mac[6] = {0x24, 0xf6, 0x77, 0x34, 0xbe, 0xed};
    uint8_t mbp_mac[6] = {0x8c, 0x85, 0x90, 0x7a, 0x3e, 0x2c};
    uint8_t mate7_1[6] = {0xb4, 0x30, 0x52, 0xfd, 0xbb, 0xf5};
    uint8_t mate7_2[6] = {0xb4, 0x30, 0x52, 0xfd, 0xba, 0xa0};
    uint8_t mi6[6] = {0xe4, 0x46, 0xda, 0x7b, 0x00, 0x86};
    uint8_t xuqi[6] = {0x0c, 0xd6, 0xbd, 0x6e, 0x4e, 0x75};
    unsigned char *d_mac = calloc(1, sizeof(unsigned char));
//    memcpy(d_mac, mi6, 6);
//    memcpy(d_mac, mate7_1, 6);
//    memcpy(d_mac, mate7_2, 6);
//    memcpy(d_mac, phone_mac, 6);
//    memcpy(d_mac, mbp_mac, 6);
//    memcpy(d_mac, phone7_2_mac, 6);
    memcpy(d_mac, mate7_1, 6);

    //int frame_type = PROBE_RESP_FRAME;
//    int frame_type = RTS_FRAME;
//    int frame_type = BEACON_FRAME;




    printf("%02x-%02x-%02x-%02x-%02x-%02x\n", s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);


//    prepareBeaconORProbeResponseFrame(d_mac, s_mac, ssid, ssid_len, PROBE_RESP_FRAME, 0);

    int i = 0;
    for (i = 0; i < packet_size; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n");
}

extern char* fake_ssids[4];

extern char * fake_ssid_1;
extern char * fake_ssid_2;
extern char * fake_ssid_3;
extern char * fake_ssid_4;

extern unsigned char *s_mac;

//实验，当终端收到多个历史SSID会回复几个
int experenment() {
    char errBuf[PCAP_ERRBUF_SIZE];

    pcap_t* device = pcap_open_live("wlx7cdd90f6cd90", 65535, 1, 1000, errBuf);
//    pcap_t* device = pcap_open_live("wlan0", 65535, 1, 1000, errBuf);
    if (NULL == device) {
        printf("设备启动失败，请检查该网卡接口是否开启");
        return 0;
    } else {
        printf("设备启动成功\n");
    }

    /*//设置过滤器
    struct bpf_program filter;
    char tmp[100];
    uint8_t mate7_1[6] = {0xb4, 0x30, 0x52, 0xfd, 0xbb, 0xf5};
    sprintf(tmp, "ether src %02X:%02X:%02X:%02X:%02X:%02X", mate7_1[0], mate7_1[1], mate7_1[2], mate7_1[3], mate7_1[4], mate7_1[5]);
    if(pcap_compile(device, &filter, tmp, 1, 0) == PCAP_ERROR) {
        printf("pcap_compile error");
        return 0;
    }

    if(pcap_setfilter(device,&filter) == PCAP_ERROR) {
        printf("pcap_setfilter error");
        return 0;
    } else {
        printf("设置过滤器 done\n");
    }


    int link_type = DLT_IEEE802_11_RADIO;
    if (link_type != pcap_datalink(device)) {
        printf("设备抓取帧与对应类型不符合");
        pcap_close(device);
        sleep(5);
        return 0;
    }*/

    printf("wlan0 pcap_loop");
    // if (-1 == pcap_loop(device, PACKETS_NUM, handle_packet, (u_char*)&cap_type.link_type)) {
    if (-1 == pcap_loop(device, -1, handle_packet, NULL)) {
        //抓包过程出现错误
        printf("抓包过程出现错误\n");
        pcap_close(device);
        sleep(5);
        return 0;
    } else {
        printf("开始抓包\n");
    }


//    printf("\n");



}

//send specified beacon frame
int experenmentForBeacon() {
    char * fake_ssid = "beacon test";
    int ssid_len = strlen(fake_ssid);

    uint8_t iphone7p_1[6] = {0x48, 0xbf, 0x6b, 0xd0, 0x7a, 0x6e};
//    uint8_t mate7_1[6] = {0xb4, 0x30, 0x52, 0xfd, 0xbb, 0xf5};
    unsigned char *d_mac = calloc(1, sizeof(unsigned char));
    memcpy(d_mac, iphone7p_1, 6);

    uint8_t ap_mac[6] = {0x7c, 0xdd, 0x90, 0xf6, 0xcd, 0x90};
    unsigned char *s_mac = calloc(1, sizeof(unsigned char));
    memcpy(s_mac, ap_mac, 6);

//    prepareBeaconORProbeResponseFrame(d_mac, s_mac, fake_ssid, ssid_len, BEACON_FRAME, 1);
    sendPcakage(0, packet, packet_size);
}


extern int socket_tcp;

int main() {
    int a = 0;
    int b = 0;

    createSocket();

    send_deeply_induced_ssid();

    printf("counterfeit_ssid_list.length=%d\n",counterfeit_ssid_list.length);

    experenment();
//    experenmentForBeacon();
}
