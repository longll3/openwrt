/*
 * 提供帧的伪造和发送的功能
 */

#ifndef  FAKEFRAMESEND_H
#define  FAKEFRAMESEND_H

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <assert.h>

//#include <netinet/ether.h>
//#include <net/ethernet.h>

#define le16_to_cpu __le16_to_cpu

uint32_t FakeRTSLength;
u_char FakeRTSFrame[128];

uint32_t  FakeProbeLength;
u_char FakeProbeResponseFrame[300];//[256];

uint32_t ssidLength;

int sockFD;
int broadcastFD;
struct sockaddr_in clientAddr;

void sendRTSFrame();
void sendProbeFrame();

/*
 *输入：伪造的源地址、ssid 
 */
u_char packetData[152]={0x00,0x00,0x24,0x00,0x2f,0x40,0x00,0xa0,0x20,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0xd7,0xd0,0xba,0x72,0x12,0x00,0x00,0x00,0x10,0x02,0x85,0x09,0xa0,0x00,0xec,0x00,0x00,0x00,0xec,0x00,0x80,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xe2,0x95,0x6e,0x41,0xbb,0xca,0xe2,0x95,0x6e,0x41,0xbb,0xca,0x30,0x0a,0xdd,0x61,0x37,0x3f,0x49,0x00,0x00,0x00,0x64,0x00,0x21,0x04,0x00,0x04,0x43,0x4d,0x43,0x43,0x01,0x08,0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24,0x03,0x01,0x06,0x07,0x06,0x55,0x53,0x20,0x01,0x0b,0x1e,0x2a,0x01,0x00,0x32,0x04,0x30,0x48,0x60,0x6c,0x3b,0x02,0x51,0x00,0x7f,0x08,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0xdd,0x18,0x00,0x50,0xf2,0x02,0x01,0x01,0x80,0x00,0x03,0xa4,0x00,0x00,0x27,0xa4,0x00,0x00,0x42,0x43,0x5e,0x00,0x62,0x32,0x2f,0x00,0xf3,0xa9,0x64,0x25};//,0x96,0x8f,0x64,0xb5};
u_char RSNTag[26]={0x30,0x18,0x01,0x00,0x00,0x0f,0xac,0x02,0x02,0x00,0x00,0x0f,0xac,0x04,0x00,0x0f,0xac,0x02,0x01,0x00,0x00,0x0f,0xac,0x02,0x0c,0x00};
u_char RSNTagsysu[22]={0x30,0x14,0x01,0x00,0x00,0x0f,0xac,0x04,0x01,0x00,0x00,0x0f,0xac,0x04,0x01,0x00,0x00,0x0f,0xac,0x01,0x00,0x00};
u_char WPATag[28]=
{0xdd,0x1a,0x00,0x50,0xf2,0x01,0x01,0x00,0x00,0x50,0xf2,0x02,0x02,0x00,0x00,0x50,0xf2,0x04,0x00,0x50,0xf2,0x02,0x01,0x00,0x00,0x50,0xf2,0x02};

void modifyProbeFrameToSend(u_char srcMac[],char *ssid){
    uint32_t packetLength = 152;
    int rtLength = packetData[2];  //the length of radiotap
    if(rtLength > packetLength){
        printf("exceeding packet size\n");
        return;
    }

    memcpy(FakeProbeResponseFrame, packetData, packetLength);
    FakeProbeLength = packetLength;

    //modify the Mac 
    int i;
    for(i=0;i<6;i++){
         FakeProbeResponseFrame[rtLength+16+i]=srcMac[i];  //BSS Id 
         FakeProbeResponseFrame[rtLength+10+i]=srcMac[i];
    }

  // modify the ssid 
    int ssidLenPos=73,curLen=strlen(ssid);
    FakeProbeResponseFrame[ssidLenPos]=curLen;
    if(curLen>4){    //4为所给的packetData里ssid的长度
        int move=curLen-4;
        for(i=packetLength+move-1;i>ssidLenPos+curLen;i--){   
            FakeProbeResponseFrame[i]=FakeProbeResponseFrame[i-move];
        }
        for(i=0;i<curLen;i++){                               
            FakeProbeResponseFrame[ssidLenPos+1+i]=ssid[i];
        }
        FakeProbeLength=packetLength+move;
    }else if(curLen<4){
        int move=4-curLen;
        FakeProbeLength=packetLength-move;
        for(i=0;i<curLen;i++){                             
            FakeProbeResponseFrame[ssidLenPos+1+i]=ssid[i];
        }
        i=ssidLenPos+1+i;
        for(;i<FakeProbeLength;i++){                       
            FakeProbeResponseFrame[i]=FakeProbeResponseFrame[i+move];
        } 
    }else{
        for(i=0;i<curLen;i++){                          
            FakeProbeResponseFrame[ssidLenPos+1+i]=ssid[i];                 
        }
    }

    //发送
    sendProbeFrame(sockFD, FakeProbeResponseFrame, FakeProbeLength);  //无加密的SSID

 /* 
    //针对WPA/WPA2加密类型的      加入RSN字段（长度是26）和WPA字段（长度28）
    FakeProbeResponseFrame[70]=0x31;  //令Capabilities Information字段的Privacy位置1,即令其支持WEP
    for(i=0;i<4;i++) {                                 //将循环校验码往后移
	FakeProbeResponseFrame[FakeProbeLength-4+i+26+28]=FakeProbeResponseFrame[FakeProbeLength-4+i];
    }    
    for(i=0;i<26;i++){                                //加入RSN字段
        FakeProbeResponseFrame[FakeProbeLength-4+i]=RSNTag[i];
    }
    for(i=0;i<28;i++){                                //加入WPA字段
        FakeProbeResponseFrame[FakeProbeLength-4+26+i]=WPATag[i];
    }
    FakeProbeLength+=26+28;


    //针对SYSUSECURE（EAP加密）类型的
    FakeProbeResponseFrame[70]=0x31;  //令Capabilities Information字段的Privacy位置1,即令其支持WEP
    for(i=0;i<4;i++) {                                 //将循环校验码往后移
        FakeProbeResponseFrame[FakeProbeLength-4+i+22]=FakeProbeResponseFrame[FakeProbeLength-4+i];
    } 
    for(i=0;i<22;i++){                                //加入RSN字段
        FakeProbeResponseFrame[FakeProbeLength-4+i]=RSNTagsysu[i];
    }
    FakeProbeLength+=22;    

    //发送
    sendProbeFrame(sockFD, FakeProbeResponseFrame, FakeProbeLength);      //有加密的SSID
 */  
}

int initBroadcastFD(char* interface){
    int sockFD = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sockFD < 0){
        perror("Create raw socket error");
        return -1;
    }
    struct ifreq interfaceRequest;
    memset((void*)&interfaceRequest, 0, sizeof(struct ifreq));
    strncpy(interfaceRequest.ifr_name, interface, sizeof(interfaceRequest.ifr_name) - 1);
    if(ioctl(sockFD, SIOGIFINDEX, &interfaceRequest) < 0){
        perror("SIOGIFINDEX error");
        return -1;
    }
    /********************bind raw socket to interface************************/
    struct sockaddr_ll sockAddr;
    memset((void*)&sockAddr, 0, sizeof(sockAddr));
    sockAddr.sll_family = AF_PACKET;
    sockAddr.sll_ifindex = interfaceRequest.ifr_ifindex;
    sockAddr.sll_protocol = htons(ETH_P_ALL);
    if(bind(sockFD, (struct sockaddr*)&sockAddr, sizeof(sockAddr)) < 0){
        perror("Raw socket binding error");
        return -1;
    }
    /********************Open promise*************************************/
    struct packet_mreq promiseSet;
    memset((void*)&promiseSet, 0, sizeof(promiseSet));
    promiseSet.mr_ifindex = sockAddr.sll_ifindex;
    promiseSet.mr_type = PACKET_MR_PROMISC;
    if(setsockopt(sockFD, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &promiseSet, sizeof(promiseSet)) < 0){
        perror("setsocketopt (promise ) failed");
        return -1;
    }
    return sockFD;
}


inline void sendRTSFrame(){
    if(write(broadcastFD, FakeRTSFrame, FakeRTSLength) < 0){
        perror("send 80211 packet error");
    }
}

inline void sendProbeFrame(){
    if(write(broadcastFD, FakeProbeResponseFrame, FakeProbeLength) < 0){
        perror("send 80211 packet error");
    }
}

#endif

