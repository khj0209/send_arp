#include "header_struct.h"

void myInfo(char* itf,u_char *mac,uint8_t *ip);
void atoiArgv(char *ip,uint8_t* rip);
void normalArp(uint8_t* mIp,u_char* mMac,uint8_t* senIp,char* dev);
int checkL3type(const u_char* pack);
void listenArp(uint8_t* senIp, u_char* senMac,char* argv);
void sendArp(struct eth_header* eth, struct arp_header* arp,char* dev);
void makeArp(uint8_t* mIp,u_char* sMac,uint8_t* senIp, struct eth_header* eth,struct arp_header* arp);
void makeAttackArp(u_char* mMac,u_char* senMac,uint8_t* tarIp,uint8_t* senIp,struct eth_header* eth,struct arp_header* arp);
void attackArp(struct eth_header* eth, struct arp_header* arp,char* dev);
