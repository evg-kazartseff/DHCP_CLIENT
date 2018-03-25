//
// Created by evgenii on 21.03.18.
//

#include <sys/ioctl.h>
#include <zconf.h>
#include "DHCP_CLIENT.h"

DHCP_CLIENT::DHCP_CLIENT(char* ifname) {
    this->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (this->sock < 0) {
        std::cerr << "Error: Can't create socket" << std::endl;
    }
    memcpy(this->if_name, ifname, IF_NAMESIZE);
    struct ifreq ifr = {};
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, strlen(ifname));
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror ("Error: SIOCGIFINDEX");
        close(sock);
    }
    if_index = ifr.ifr_ifindex;
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror ("Error: SIOCGIFHWADDR");
        close(sock);
    }
    memcpy(this->client.mac, ifr.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);

    this->len.l_ethhdr = sizeof(Ethhdr);
    this->len.l_iphdr = sizeof(Iphdr);
    this->len.l_udphdr = sizeof(Udphdr);
    this->len.l_dhcppac = sizeof(Dhcp_packet);
    this->len.l_udppac = this->len.l_udphdr + this->len.l_dhcppac;
    this->len.l_ippac = this->len.l_iphdr + this->len.l_udppac;
    this->len.l_ethpac = this->len.l_ethhdr + this->len.l_ippac;

    this->offset.goto_iphdr = this->len.l_ethhdr;
    this->offset.goto_udphdr = this->len.l_ethhdr + this->len.l_iphdr;
    this->offset.goto_dhcppac = this->len.l_ethhdr + this->len.l_iphdr + this->len.l_udphdr;
    srand((unsigned int) time(nullptr));
}

int DHCP_CLIENT::DHCP_Init() {

}

char* DHCP_CLIENT::get_DHCPDISCOVER_packet() {
    auto* packet = new char[MAX_SIZE_PACKET];
    auto* eth_hdr = (Ethhdr*) packet;
    auto* ip_hdr = (Iphdr*) (packet + this->offset.goto_iphdr);
    auto* udp_hdr = (Udphdr*) (packet + this->offset.goto_udphdr);
    auto* Dhcp_pac= (Dhcp_packet*) (packet + this->offset.goto_dhcppac);

    Fill_eth_hdr(eth_hdr);
    Fill_ip_hdr(ip_hdr);
    Fill_udp_hdr(udp_hdr);
}

int DHCP_CLIENT::Fill_eth_hdr(Ethhdr* ethhdr) {
    memcpy(ethhdr->ether_dhost, this->servers.mac, ETH_ALEN);
    memcpy(ethhdr->ether_shost, this->client.mac, ETH_ALEN);
    ethhdr->ether_type = htons(ETH_P_IP);
    return 0;
}

int DHCP_CLIENT::Fill_ip_hdr(Iphdr* iphdr) {
    iphdr->version = IPVERSION;
    iphdr->ihl = 5;
    iphdr->tos = 0;
    iphdr->tot_len = htons(static_cast<uint16_t>(this->len.l_ippac));
    iphdr->id = htons(static_cast<uint16_t>(random()));
    iphdr->frag_off = 64;
    iphdr->ttl = IPDEFTTL;
    iphdr->protocol = IPPROTO_UDP;
    iphdr->check = 0;
    iphdr->daddr = inet_addr(this->servers.ipaddr);
    iphdr->saddr = inet_addr(this->client.ipaddr);
}

int DHCP_CLIENT::Fill_udp_hdr(Udphdr* udphdr) {
    udphdr->source = htons(this->client.port);
    udphdr->dest = htons(this->servers.port);
    udphdr->len = htons(static_cast<uint16_t>(this->len.l_udppac));
    udphdr->check = 0;
}
