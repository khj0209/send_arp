#pragma once
#include <stdint.h>
#include <pcap/pcap.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */

struct eth_header{
    uint8_t dstMac[6];
    uint8_t srcMac[6];
    uint8_t l3Type[2] = {0x08,0x06};
};

struct arp_header{
    uint8_t hwType[2] = {0x00,0x01};
    uint8_t prtType[2] = {0x08,0x00};
    uint8_t hwAddLen = 6;
    uint8_t prtAddLen = 4;
    uint8_t opCode[2] = {0x00,0x01};
    u_char sMac[6];
    uint8_t sIp[4];
    u_char dMac[6];
    uint8_t dIp[4];
};
