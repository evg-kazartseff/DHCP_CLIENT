//
// Created by evgenii on 21.03.18.
//

#ifndef DHCP_CLIENT_DHCP_CLIENT_H
#define DHCP_CLIENT_DHCP_CLIENT_H

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <cstring>
#include <net/if.h>
#include <arpa/inet.h>
#include <ctime>

#define MAX_DHCP_CHADDR_LENGTH      16
#define MAX_DHCP_SNAME_LENGTH       64
#define MAX_DHCP_FILE_LENGTH        128
#define MAX_DHCP_OPTIONS_LENGTH     312

typedef struct dhcp_packet_struct {
    u_int8_t  op;                   /* packet type */
    u_int8_t  htype;                /* type of hardware address for this machine (Ethernet, etc) */
    u_int8_t  hlen;                 /* length of hardware address (of this machine) */
    u_int8_t  hops;                 /* hops */
    u_int32_t xid;                  /* random transaction id number - chosen by this machine */
    u_int16_t secs;                 /* seconds used in timing */
    u_int16_t flags;                /* flags */
    struct in_addr ciaddr;          /* IP address of this machine (if we already have one) */
    struct in_addr yiaddr;          /* IP address of this machine (offered by the DHCP server) */
    struct in_addr siaddr;          /* IP address of DHCP server */
    struct in_addr giaddr;          /* IP address of DHCP relay */
    unsigned char chaddr [MAX_DHCP_CHADDR_LENGTH];      /* hardware address of this machine */
    char sname [MAX_DHCP_SNAME_LENGTH];    /* name of DHCP server */
    char file [MAX_DHCP_FILE_LENGTH];      /* boot file name (used for diskless booting?) */
    uint32_t    magic_cookie;
    char options[MAX_DHCP_OPTIONS_LENGTH];  /* options */
} Dhcp_packet;

typedef struct ether_header Ethhdr;
typedef struct iphdr Iphdr;
typedef struct udphdr Udphdr;

#define MAX_SIZE_PACKET             594
#define DHCP_SERVER_PORT            67
#define DHCP_CLIENT_PORT            68

class DHCP_CLIENT {
private:
    struct Len {
        size_t l_ethhdr;
        size_t l_iphdr;
        size_t l_udphdr;
        size_t l_dhcppac;
        size_t l_ethpac;
        size_t l_ippac;
        size_t l_udppac;
    };
    struct Len len;
    struct Offset {
        size_t goto_iphdr;
        size_t goto_udphdr;
        size_t goto_dhcppac;
    };
    struct Offset offset;
    struct ServersEndPoint {
        uint8_t mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        char* ipaddr = const_cast<char*>("255.255.255.255");
        uint16_t port = DHCP_SERVER_PORT;
    };
    struct ServersEndPoint servers;
    struct ClientEndPoint {
        uint8_t mac[ETH_ALEN] = {};
        char* ipaddr = const_cast<char*>("0.0.0.0");
        uint16_t port = DHCP_CLIENT_PORT;
    };
    struct ClientEndPoint client;
    int sock;
    char* if_name[IF_NAMESIZE];
    int if_index;

    char* get_DHCPDISCOVER_packet();
    int Fill_eth_hdr(Ethhdr* ethhdr);
    int Fill_ip_hdr(Iphdr* iphdr);
    int Fill_udp_hdr(Udphdr* udphdr);
public:
    explicit DHCP_CLIENT(char* ifname);

    int DHCP_Init();
};

#endif //DHCP_CLIENT_DHCP_CLIENT_H
