#include"packet_func.h"

void makeArp(uint8_t* mIp,u_char* sMac,uint8_t* senIp, struct eth_header* eth,struct arp_header* arp){
    u_char broad[6] ={255,255,255,255,255,255};
    u_char zr[6] ={0};

    memcpy(eth->dstMac,broad,6);
    memcpy(eth->srcMac,sMac,6);
    arp->opCode[0] = {0x00};
    arp->opCode[1] = {0x01};
    memcpy(arp->sMac,sMac,6);
    memcpy(arp->sIp,mIp,4);
    memcpy(arp->dMac,zr,6);
    memcpy(arp->dIp,senIp,4);
}
void sendArp(struct eth_header* eth, struct arp_header* arp,char* dev){
    u_char packet[42];
    memcpy(packet,eth,14);
    memcpy(packet+14,arp,28);
    for(int i = 0; i< 42; i++){
        printf("%02X ",packet[i]);
    }
    printf("\n");

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(dev
                , BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return ;
    }

    pcap_sendpacket(handle,packet,42);
}

void normalArp(uint8_t* mIp,u_char* mMac,uint8_t* senIp,char* dev){
    struct eth_header eth;
    struct arp_header arp;
    makeArp(mIp,mMac,senIp, &eth, &arp);
    sendArp(&eth,&arp,dev);
}
