//
// Created by longll on 18-11-27.
//

#include "make_packet.h"

extern u_char * rts_frame;
extern uint8_t frame[256];
extern int frame_len;


int pad_packet(char *ssid, int ssid_len, unsigned char *s_mac, unsigned char *d_mac,
               int frame_type, int encrytion_mode, int channel, char *packet, int packet_size)
{
    int len;
    static int sequence_num = 0;
    memset(packet, 0, packet_size);

    if (frame_type == RTS_FRAME) {
        return pad_rts_packet(frame_type, s_mac, d_mac, packet_size, packet);
    }


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


int pad_rts_packet(int frame_type, unsigned char *s_mac, unsigned char *d_mac, int packet_size, char * packet) {
    int len;
    memset(packet, 0, packet_size);

    //RADIOTAP
    memcpy(packet, frame, radiptapLength+4);
    len = radiptapLength+4;

    uint8_t duration[2] = {0xa8, 0x00};


    unsigned char *dura = calloc(1, sizeof(unsigned char));
    memcpy(dura, duration, 2);

    //RTS
    if(frame_type == RTS_FRAME)
    {
//        memcpy(packet + len, RTS, sizeof(RTS)-1);
//        memcpy(packet + len+2, dura, 2);

        memcpy(packet+len, d_mac, 6);
        memcpy(packet+len+6, s_mac, 6);
        len = len + 6 + 6;
    }
    //CTS
    if(frame_type == CTS_FRAME)
    {
        //to do
    }

    return len;
}

extern int packet_size;
extern unsigned char packet[256];

int prepareBeaconORProbeResponseFrame(char* d_mac, char* s_mac, char* ssid, int ssid_len, int frame_type, int encryption_mode) {
    int channel = 7;
    packet_size = pad_packet(ssid, ssid_len, s_mac, d_mac, frame_type, encryption_mode, channel, &packet, packet_size);
    return packet_size;

}