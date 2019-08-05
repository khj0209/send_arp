#include "packet_func.h"

int checkL3type(const u_char* pack){
    if(pack[12]==0x08&&pack[13]==0x06) return 0;
    else return -1;
}
int checkReply(struct arp_header arp,uint8_t* senIp){
    printf("%d\n",arp.sIp[3]);
    if(arp.opCode[1] == 0x02){
        if(arp.sIp[3] == senIp[3]) {
            printf("hi");
            return 0;
        }
        else return -1;
    }
    else return -1;
}
void listenArp(char* argv,uint8_t* senIp, u_char* senMac){
    char* dev = argv;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    int success=0;
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return ;
    }

    while (success == 0) {
        printf("Listening\n");
        struct pcap_pkthdr* header;
        struct arp_header arp;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        if(!checkL3type(&packet[0])) {
            memcpy(&arp,packet+14,28);
            for (int i = 0;i<2;i++) {
                printf("%02X",arp.opCode[i]);
            }
            printf("\n");
            if(checkReply(arp,senIp)==0){
                success = -1;
                for(int i = 0;i<6;i++){
                    senMac[i] = arp.sMac[i];
                    printf("%02X:",senMac[i]);
                }
                printf("\n");
            }
        }
    }
    pcap_close(handle);
}
