//
// Created by longll on 18-12-9.
//

#include "sendPacket.h"
#include "ieee80211.h"

extern int packet_size;
extern unsigned char packet[256];

struct sockaddr_ll sockAddr;




int sendPcakage(int send_times, unsigned char pkt[256], int pkt_size) {
    send_times = 1;
    static int sk;
    if (sk == 0) {
        printf("未绑定套接字\n");

        /********************bind raw socket to interface************************/
        memset((void*)&sockAddr, 0, sizeof(sockAddr));



        sockAddr.sll_family = PF_PACKET;
        sockAddr.sll_ifindex = if_nametoindex("wlx7cdd90f6cd90");
//        sockAddr.sll_ifindex = if_nametoindex("wlan0");
        sockAddr.sll_protocol = htons(0x88cc);

        /**
        sockAddr.sll_addr[0] = 0x48;
        sockAddr.sll_addr[1] = 0xbf;
        sockAddr.sll_addr[2] = 0x6b;
        sockAddr.sll_addr[3] = 0xd0;
        sockAddr.sll_addr[3] = 0x7a;
        sockAddr.sll_addr[3] = 0x6e;
         */


        //sockAddr.sll_protocol = htons(0x88cc);


        /**
         * htons() -> host to network short 将主机的无符号短整形数转换成网络字节顺序。
         * 将主机字节顺序转换为网络字节顺序。
         * 网络字节顺序（NBO， network byte order）,网络上统一使用按从高到低的顺序存储，避免兼容性问题
         * 主机字节顺序（HBO， host byte order），与CPU设计有关，与操作系统无关，有大小端2种方式
         */
        sk = socket(PF_PACKET, SOCK_RAW, htons(0x88cc));
        //int sk = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if(sk < 0){
            perror("Create raw socket error");
            return -1;
        }

        if(bind(sk, (struct sockaddr*)&sockAddr, sizeof(sockAddr)) < 0){
            perror("Raw socket binding error");
            return -1;
        }
    } else {
//        printf("sk: %d\n", sk);
    }

    int i = 0;
    //发送无数次
    if (send_times == 0) {
        i = 1;
        while (i++) {
//            printf("%d\n", i);
            int ret = sendto(sk, pkt, pkt_size, 0, (struct sockaddr*)&sockAddr, sizeof(struct sockaddr_ll));
            if (ret == -1) {
                printf("send failure, send again\n");
                sendto(sk, pkt, pkt_size, 0, (struct sockaddr*)&sockAddr, sizeof(struct sockaddr_ll));
            } else {
//                printf("send successful\n");
            }

        }
    } else {
        while(i < send_times) {
//            printf("%d\n", i);
//        for (i = 0; i < len; i++) {
//            printf("%02x ", packet[i]);
//        }
//        printf("\n");
            int ret = sendto(sk, pkt, pkt_size, 0, (struct sockaddr*)&sockAddr, sizeof(struct sockaddr_ll));
            if (ret == -1) {
                return -1;
            } else {
//                printf("send successful\n");
            }

            i++;
        }
        return 0;
    }





}
