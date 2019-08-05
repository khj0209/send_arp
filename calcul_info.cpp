#include "packet_func.h"
#include <arpa/inet.h>
#include <byteswap.h>

void myInfo(char* itf,u_char *mac, uint8_t *ip){
    struct ifreq ifr;
    strncpy(ifr.ifr_name, itf, sizeof(itf) - 1);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0 || ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        return;
    }
    close(sock);
    for (int i = 0; i < 4; i++)
        ip[i] = static_cast<uint8_t>(ifr.ifr_addr.sa_data[i + 2]);

    int sock2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock2 < 0 || ioctl(sock2, SIOCGIFHWADDR, &ifr) < 0) {
        return;
    }
    close(sock2);

    for (int i = 0; i < 6; i++)
        mac[i] = static_cast<uint8_t>(ifr.ifr_hwaddr.sa_data[i]);
}
void atoiArgv(char *ip,uint8_t* rip){
    uint32_t tmp = inet_addr(ip);
    memcpy(rip,&tmp,4);
}
