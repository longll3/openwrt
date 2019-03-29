//
// Created by root on 1/26/19.
//

#ifndef LURE_MSG_H
#define LURE_MSG_H

#endif //LURE_MSG_H

#ifndef _MSG_H_
#define _MSG_H_

#define VERSION_SIZE  10   //版本长度
#define COMMAND_SIZE  10   //命令长度
#define ID_SIZE       18   //设备ID长度
#define NAME_SIZE     64   //首部行字段名称长度
#define VAL_SIZE      256   //首部行字段值长度
#define HEADLINE_NUM  32   //首部行字段总数
#define BODY_SIZE     1024*300 //实体长度
#define PACKET_MAXLEN 4196 //一个包最大长度 1024 * 4
#define SEP           "|" //分隔符
#define SEP_SIZE      1
#define LSEP          "\n" //换行符
#define LSEP_SIZE     1
#define VERSION       "DYD1.0"
#define FIELD_SEP     ("\t")		/* 字段值之间的分隔符 */

typedef unsigned char Byte;

enum DEV_STATUS{
    STATUS_ONLINE = 1,
    STATUS_OTHER = 99
};

/**
 * @author longll
 * @description 用于转发80211帧和以太网帧的枚举类型
 */
enum FRAME_TYPE {
    PROBE_REQUEST_FRAME = 1,
    ETHERNET_FRAME = 2,
    BEAT_DATA = 3,
    ASK_SSID = 4

};

enum MESSAGE_TYPE {
    SSID_LIST = 1
};

enum TELEGRAM_TYPE{
    //data_type is a 32bit integer.One bit is represent one data type
    /**<
    固定采集设备,   DETECT_DEVICE_TYPE=1;
    移动车载采集设备,  DETECT_DEVICE_TYPE=2;
    单兵采集设备,  DETECT_DEVICE_TYPE=3 */
            SMART_EP_1001 = 1001,  //bit 1, Terminal feature information(终端特征信息)
    SMART_AP_1002 = 1002,  //bit 2, Access Point feature information(被采集热点信息)
    SMART_TRAJECTORY = 1003,   //bit 5, Mobile detected device trajectory information(终端特征移动采集设备轨迹信息)
    SMART_HEARTBEAT = 1007,   //Detected device status(前端采集设备状态)

    /**< self-defined standard */
            SMART_GET_ORDER = 9000,
    SMART_EXT_EP = 9001, //bit 6
    SMART_STATUS = 9002,
    SMART_BASIC = 9003,
    SMART_EXT_AP_EP = 9004, //bit 7
    SMART_BINDING_SHOP = 9005
};

typedef struct {
    char name[NAME_SIZE];
    char val[VAL_SIZE];
} HEADLINE;

typedef struct {
    char version[VERSION_SIZE];
    char command[COMMAND_SIZE];
    char dev_id[ID_SIZE];
    int hl_num;
    HEADLINE headlines[HEADLINE_NUM];
    char body[BODY_SIZE];
} PACKET;

typedef struct {
    int datatype;
    int content_length;
    char content[0];//flexible array
}TELEGRAM;

int msg2packet(const char* msg, PACKET* pkt);

int constructTelegram(TELEGRAM **heartbeat_tele, enum TELEGRAM_TYPE telegramtype, const int content_length, const Byte *content);
#endif
