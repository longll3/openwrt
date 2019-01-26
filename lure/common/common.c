//
// Created by root on 18-12-23.
//

#include "common.h"

#include <stdio.h>

int ifFakeMAC(unsigned char *mac) {
    /*简单的说对于MAC地址 12 : 34 : 56 : 78 : 9A : BC  , 仅仅只需要看看第一个字节(12)的最后两个比特, 是否为10, 为10大部分情况下都为随机地址(除了一些特殊用途),
    所以对于第二个数是2, 6, A, E , 可以判断他为随机地址*/
    unsigned char c = (unsigned char)((mac[0] << 6));

    printf("%02X\n", c);

    int *a = (int *)mac;
    if (c == 0x80 || 0 == (*a)){
        return 1;
    }

    return 0;
}