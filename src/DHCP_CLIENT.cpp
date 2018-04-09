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
        perror("Error: SIOCGIFINDEX");
        close(sock);
    }
    if_index = ifr.ifr_ifindex;
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Error: SIOCGIFHWADDR");
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
    unsigned int delay = static_cast<unsigned int>(random() % 10 + 1);
    std::cout << delay << std::endl;
    sleep(delay);
    char* packet = get_DHCPDISCOVER_packet();
}

char* DHCP_CLIENT::get_DHCPDISCOVER_packet() {
    auto* packet = new char[MAX_SIZE_PACKET];
    memset(packet, 0, MAX_SIZE_PACKET);
    auto* eth_hdr = (Ethhdr*) packet;
    auto* ip_hdr = (Iphdr*) (packet + this->offset.goto_iphdr);
    auto* udp_hdr = (Udphdr*) (packet + this->offset.goto_udphdr);
    auto* Dhcp_pack = (Dhcp_packet*) (packet + this->offset.goto_dhcppac);


    Fill_eth_hdr(eth_hdr);
    Fill_ip_hdr(ip_hdr);
    Fill_udp_hdr(udp_hdr);
    Fill_base_dhcp_pac(Dhcp_pack);

    uint32_t cur = 4;
    char option = DHCPDISCOVER;
    cur = Fill_dhcp_options(Dhcp_pack, cur, DHCP_OPTION_MESSAGE_TYPE, 0x01, &option);

    Ip_csum(ip_hdr);
    Udp_csum(ip_hdr, udp_hdr);

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
    return 0;
}

int DHCP_CLIENT::Fill_udp_hdr(Udphdr* udphdr) {
    udphdr->source = htons(this->client.port);
    udphdr->dest = htons(this->servers.port);
    udphdr->len = htons(static_cast<uint16_t>(this->len.l_udppac));
    udphdr->check = 0;
    return 0;
}

int DHCP_CLIENT::Fill_base_dhcp_pac(Dhcp_packet* dhcp) {
    dhcp->op = BOOTREQUEST;
    dhcp->htype = ETHERNET_HARDWARE_ADDRESS;
    dhcp->hlen = ETH_ALEN;
    dhcp->hops = 0;
    this->packet_xid = static_cast<uint32_t>(random());
    dhcp->xid = htonl(this->packet_xid);
    dhcp->secs = 0xFF;
    dhcp->flags = 0x0; //htons(DHCP_BROADCAST_FLAG); /// попробовать 0
    /* our hardware address */
    memcpy(dhcp->chaddr, this->client.mac, ETH_ALEN);

    /* first four bytes of options field is magic cookie (as per RFC 2132) */
    dhcp->options[0] = 0x63;
    dhcp->options[1] = 0x82;
    dhcp->options[2] = 0x53;
    dhcp->options[3] = 0x63;
}

int DHCP_CLIENT::Ip_csum(Iphdr* iphdr) {
    uint16_t sum = csum(reinterpret_cast<uint16_t*>(iphdr), this->len.l_iphdr);
    iphdr->check = sum;
    return 0;
}

struct pseudo_header {
    in_addr_t source_address;
    in_addr_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

int DHCP_CLIENT::Udp_csum(Iphdr* ippac, Udphdr* udppac) {
    Iphdr* iph = ippac;
    Udphdr* udph = udppac;
    size_t udpplen = 0;
    unsigned char* block = nullptr;

    struct pseudo_header* ph = nullptr;
    size_t phlen = sizeof(struct pseudo_header);

    udpplen = this->len.l_udppac;

    ph = new struct pseudo_header;

    ph->source_address = iph->saddr;
    ph->dest_address = iph->daddr;
    ph->placeholder = 0;
    ph->protocol = iph->protocol;
    ph->udp_length = udph->len;

    block = new unsigned char[phlen + udpplen];

    udph->check = 0;

    memcpy(block, ph, phlen);
    memcpy(block + phlen, udph, udpplen);
    delete ph;

    udph->check = csum((uint16_t*) block, phlen + udpplen);
    delete block;
    return 0;
}

uint16_t DHCP_CLIENT::csum(uint16_t* ptr, size_t len) {
    size_t nleft = len;
    uint32_t sum = 0;
    uint16_t* w = ptr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(unsigned char*) (&answer) = *(unsigned char*) w;
        sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);     /* add carry */
    answer = (uint16_t) ~sum;     /* truncate to 16 bits */
    return (answer);
}

int DHCP_CLIENT::DHCP_Get_OFFER() {
    return 0;
}

uint32_t DHCP_CLIENT::Fill_dhcp_options(Dhcp_packet* DHCP_pack, uint32_t cur, uint8_t type, uint8_t len, char* option) {
    std::cout << cur << std::endl;
    DHCP_pack->options[cur++] = type;
    DHCP_pack->options[cur++] = len;
    memcpy(DHCP_pack->options + cur, option, len);
    return cur + len;
}
