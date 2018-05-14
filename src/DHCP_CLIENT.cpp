//
// Created by evgenii on 21.03.18.
//
#include <sys/time.h>
#include "DHCP_CLIENT.h"

DHCP_CLIENT::DHCP_CLIENT(char* ifname) {
    this->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (this->sock < 0) {
        std::cerr << "Error: Can't create socket" << std::endl;
    }
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = RECV_TIMEOUT_USEC;
    setsockopt(this->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    int on = 1;
    setsockopt(this->sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
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
    gethostname(hostname, HOST_NAME_MAX);

    memset(&addr_ll, 0, sizeof(struct sockaddr_ll));
    addr_ll.sll_family = AF_PACKET;
    addr_ll.sll_ifindex = this->if_index;
    addr_ll.sll_halen = ETH_ALEN;
    addr_ll.sll_pkttype = PACKET_OUTGOING;
    memcpy(addr_ll.sll_addr, this->servers.mac, ETH_ALEN);
    addr_ll.sll_protocol = htons(ETH_P_IP);

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

    this->select_timeout = 300; // milisecond * 10 usec in socket tumeout
    this->Error = NO_ERROR;
}

int DHCP_CLIENT::DHCP_Init() {
    unsigned int delay = static_cast<unsigned int>(random() % 10 + 1);
    std::cout << delay << std::endl;
   // sleep(delay);
    char* packet = get_DHCPDISCOVER_packet();

    if (sendto(this->sock, packet, MAX_SIZE_PACKET, 0, (struct sockaddr*) &this->addr_ll, sizeof(struct sockaddr_ll)) < 0) {
        this->Error = SEND_ERROR;
        delete packet;
        return EXIT_FAILURE;
    }
    delete packet;

    return EXIT_SUCCESS;
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

    uint32_t cur = 0;
    char option = DHCPDISCOVER;
    cur = Fill_dhcp_options(Dhcp_pack, cur, DHCP_OPTION_MESSAGE_TYPE, 0x01, &option);
    Dhcp_pack->options[cur] = static_cast<char>(DHCP_OPTION_END);

    Ip_csum(ip_hdr);
    Udp_csum(ip_hdr, udp_hdr);
    return packet;
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
    dhcp->secs = 0x00;
    dhcp->flags = 0x00;
    /* our hardware address */
    memcpy(dhcp->chaddr, this->client.mac, ETH_ALEN);

    /* field is magic cookie (as per RFC 2132) */
    dhcp->magic_cookie = DHCP_MAGIC_COOKIE;
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

uint32_t DHCP_CLIENT::Fill_dhcp_options(Dhcp_packet* DHCP_pack, uint32_t cur, uint8_t type, uint8_t len, char* option) {
    DHCP_pack->options[cur++] = type;
    DHCP_pack->options[cur++] = len;
    memcpy(DHCP_pack->options + cur, option, len);
    return cur + len;
}

int DHCP_CLIENT::Get_DHCPOFFER_packets() {
    uint32_t socklen;
    struct sockaddr_in recv_addrin;
    memset(&recv_addrin, 0, sizeof(struct sockaddr_in));
    ssize_t bytes_read;
    size_t wait = this->select_timeout;
    char* pac = nullptr;
    while (wait--) {
        if (!pac)
            pac = new char[MAX_SIZE_PACKET];
        bytes_read = recvfrom(this->sock, pac, MAX_SIZE_PACKET, 0, (struct sockaddr*) &recv_addrin, &socklen);
        if (bytes_read == EAGAIN || bytes_read <= 0) {
            continue;
        }
        auto* eth_hdr = (Ethhdr*) pac;
        auto* udp_hdr = (Udphdr*) (pac + this->offset.goto_udphdr);
        auto* dhcp_pack = (Dhcp_packet*) (pac + this->offset.goto_dhcppac);
        if (ntohs(udp_hdr->dest) == this->client.port)
            if (memcmp(eth_hdr->ether_dhost, this->client.mac, ETH_ALEN) == 0 || memcmp(eth_hdr->ether_dhost, this->servers.mac, ETH_ALEN) == 0)
                if (ntohl(dhcp_pack->xid) == this->packet_xid) {
                    int cur = Find_DHCP_option(dhcp_pack, DHCP_OPTION_MESSAGE_TYPE);
                    if (cur != -1) {
                        if (dhcp_pack->options[cur + 2] == DHCPOFFER) {
                            this->DHCPOFFER_queue.push(pac);
                            pac = nullptr;
                        }
                    }
                }
    }
    if (this->DHCPOFFER_queue.empty())
        return EXIT_FAILURE;
    else
        return EXIT_SUCCESS;
}

int DHCP_CLIENT::DHCP_Select() {
    if (this->Get_DHCPOFFER_packets() == EXIT_FAILURE) {
        this->Error = DHCP_SERVERS_NOT_RESPOND;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int DHCP_CLIENT::DHCP_Request() {
    if (this->DHCPOFFER_queue.empty()) {
        this->Error = DHCP_SERVERS_NOT_RESPOND;
        return EXIT_FAILURE;
    }
    char* OFFER = this->DHCPOFFER_queue.front();
    this->DHCPOFFER_queue.pop();
    auto* offer_dhcp_pack = (Dhcp_packet*) (OFFER + this->offset.goto_dhcppac);
    struct in_addr offer_ip = offer_dhcp_pack->yiaddr;
    delete OFFER;

    char* REQUEST = this->get_DHCPREQUEST_packet(offer_ip);
    if (sendto(this->sock, REQUEST, MAX_SIZE_PACKET, 0, (struct sockaddr*) &this->addr_ll, sizeof(struct sockaddr_ll)) < 0) {
        this->Error = SEND_ERROR;
        delete REQUEST;
        return EXIT_FAILURE;
    }
    delete REQUEST;

    char* ACK = this->get_DHCPACK_packet();
    this->timing.time_ACK = this->get_time();
    this->DHCPPACK_buff.push(ACK);
    return EXIT_SUCCESS;
}

char* DHCP_CLIENT::get_DHCPREQUEST_packet(in_addr offer_ip) {
    char* packet = new char[MAX_SIZE_PACKET];
    memset(packet, 0, MAX_SIZE_PACKET);
    auto* eth_hdr = (Ethhdr*) packet;
    auto* ip_hdr = (Iphdr*) (packet + this->offset.goto_iphdr);
    auto* udp_hdr = (Udphdr*) (packet + this->offset.goto_udphdr);
    auto* Dhcp_pack = (Dhcp_packet*) (packet + this->offset.goto_dhcppac);


    Fill_eth_hdr(eth_hdr);
    Fill_ip_hdr(ip_hdr);
    Fill_udp_hdr(udp_hdr);
    Fill_base_dhcp_pac(Dhcp_pack);

    char off_ip[4];
    memcpy(off_ip, &offer_ip.s_addr, 4);

    uint32_t cur = 0;
    char option = DHCPREQUEST;
    cur = Fill_dhcp_options(Dhcp_pack, cur, DHCP_OPTION_MESSAGE_TYPE, 1, &option);
    cur = Fill_dhcp_options(Dhcp_pack, cur, DHCP_OPTION_REQUESTED_ADDRESS, IP_ALEN, off_ip);
    cur = Fill_dhcp_options(Dhcp_pack, cur, DHCP_OPTION_HOST_NAME, static_cast<uint8_t>(strlen(this->hostname)), this->hostname);

    unsigned char parameter_request_list[16];
    parameter_request_list[0] = 1;      // Subnet Mask
    parameter_request_list[1] = DHCP_OPTION_BROADCAST_ADDRESS;     // Broadcast Address
    parameter_request_list[2] = 2;      // Time Offset
    parameter_request_list[3] = 3;      // Router
    parameter_request_list[4] = 15;     // Domain Name
    parameter_request_list[5] = 6;      // Domain Name Server
    parameter_request_list[6] = 119;    // Domain Search
    parameter_request_list[7] = DHCP_OPTION_HOST_NAME;     // Host Name
    parameter_request_list[8] = 44;     // NetBIOS over TCP/IP Name Server
    parameter_request_list[9] = 47;     // NetBIOS over TCP/IP Scope
    parameter_request_list[10] = 26;    // Interface MTU
    parameter_request_list[11] = 121;   // Classless Static Route
    parameter_request_list[12] = 42;    // Network Time Protocol Servers
    parameter_request_list[13] = 249;   // Private/Classless Static Route (Microsoft)
    parameter_request_list[14] = 33;    // Static Route
    parameter_request_list[15] = 252;   // Private/Proxy autodiscovery

    cur = Fill_dhcp_options(Dhcp_pack, cur, DHCP_OPTION_REQUEST_LIST, 16, reinterpret_cast<char*>(parameter_request_list));
    Dhcp_pack->options[cur] = static_cast<char>(DHCP_OPTION_END);

    Ip_csum(ip_hdr);
    Udp_csum(ip_hdr, udp_hdr);
    return packet;
}

int DHCP_CLIENT::DHCP_Error_Hadler() {
    switch (this->Error) {
        case DHCP_SERVERS_NOT_RESPOND:
            std::cerr << "Dhcp servers do not respond" << std::endl;
            break;
        case SEND_ERROR:
            std::cerr << "Error send" << std::endl;
            break;
        case DHCPACK_BUFF_IS_EMPTY:
            std::cerr << "Serer didn't send DHCPACK packet" << std::endl;
            break;
        default:
            break;
    }
    return EXIT_SUCCESS;
}

char* DHCP_CLIENT::get_DHCPACK_packet() {
    bool packet_get = false;
    uint32_t socklen;
    struct sockaddr_in recv_addrin {};
    memset(&recv_addrin, 0, sizeof(struct sockaddr_in));
    ssize_t bytes_read;
    size_t wait = this->select_timeout;
    auto* pack = new char[MAX_SIZE_PACKET];
    while (wait--) {
        bytes_read = recvfrom(this->sock, pack, MAX_SIZE_PACKET, 0, (struct sockaddr*) &recv_addrin, &socklen);
        if (bytes_read == EAGAIN || bytes_read <= 0) {
            continue;
        }
        auto* eth_hdr = (Ethhdr*) pack;
        auto* udp_hdr = (Udphdr*) (pack + this->offset.goto_udphdr);
        auto* dhcp_pack = (Dhcp_packet*) (pack + this->offset.goto_dhcppac);
        if (ntohs(udp_hdr->dest) == this->client.port) {
            if (memcmp(eth_hdr->ether_dhost, this->client.mac, ETH_ALEN) == 0 || memcmp(eth_hdr->ether_dhost, this->servers.mac, ETH_ALEN) == 0) {
                if (ntohl(dhcp_pack->xid) == this->packet_xid) {
                    int cur = Find_DHCP_option(dhcp_pack, DHCP_OPTION_MESSAGE_TYPE);
                    if (cur != -1) {
                        if (dhcp_pack->options[cur + 2] == DHCPACK) {
                            packet_get = true;
                            break;
                        }
                    }
                }
            }
        }
    }
    if (packet_get)
        return pack;
    else
        return nullptr;
}

int DHCP_CLIENT::DHCP_Test_ARP() {
    if (this->DHCPPACK_buff.empty()) {
        this->Error = DHCPACK_BUFF_IS_EMPTY;
        return EXIT_FAILURE;
    }
    char* DHCPACK_packet = this->DHCPPACK_buff.front();
    auto* dhcppack = (Dhcp_packet *) (DHCPACK_packet + this->offset.goto_dhcppac);
    char ip[4];
    memcpy(ip, &dhcppack->yiaddr, 4);
    auto* ARPREQ = this->get_ARPREQUEST(ip);
    if (sendto(this->sock, ARPREQ, ARP_PACKET_LEN, 0, (struct sockaddr*) &this->addr_ll, sizeof(struct sockaddr_ll)) < 0) {
        this->Error = SEND_ERROR;
        delete ARPREQ;
        return EXIT_FAILURE;
    }
    delete ARPREQ;
    if (get_ARPREPLY(ip)) {
        return ARP_FAIL;
    }
    return EXIT_SUCCESS;
}

char* DHCP_CLIENT::get_ARPREQUEST(char* target_ip) {
    uint32_t size_packet = sizeof(Ethhdr) + sizeof(Arphdr);
    auto* arp = new char[size_packet];
    memset(arp, 0, size_packet);
    auto* eth_hdr = (Ethhdr*) arp;
    auto* arp_hdr = (Arphdr*) (arp + sizeof(Ethhdr));
    memcpy(eth_hdr->ether_dhost, this->servers.mac, ETH_ALEN);
    memcpy(eth_hdr->ether_shost, this->client.mac, ETH_ALEN);
    eth_hdr->ether_type = htons(ETH_P_ARP);
    arp_hdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp_hdr->ea_hdr.ar_hln = ETH_ALEN;
    arp_hdr->ea_hdr.ar_pln = IP_ALEN;
    arp_hdr->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(arp_hdr->arp_sha, this->client.mac, ETH_ALEN);
    memcpy(arp_hdr->arp_tpa, target_ip, IP_ALEN);
    return arp;
}

int32_t DHCP_CLIENT::Find_DHCP_option(Dhcp_packet* DHCP_pack, char option) {
    int i;
    for (i = 0; DHCP_pack->options[i] != option || DHCP_pack->options[i] == DHCP_OPTION_END; i += (DHCP_pack->options[i + 1] + 2));
    if (DHCP_pack->options[i] == DHCP_OPTION_END) return -1;
    return i;
}

bool DHCP_CLIENT::get_ARPREPLY(char* ip_from) {
    uint32_t socklen;
    struct sockaddr_in recv_addrin;
    memset(&recv_addrin, 0, sizeof(struct sockaddr_in));
    ssize_t bytes_read;
    size_t wait = this->select_timeout / 2;
    char* pac = new char[MAX_SIZE_PACKET];
    while (wait--) {
        bytes_read = recvfrom(this->sock, pac, MAX_SIZE_PACKET, 0, (struct sockaddr*) &recv_addrin, &socklen);
        if (bytes_read == EAGAIN || bytes_read <= 0) {
            continue;
        }
        auto* eth_hdr = (Ethhdr*) pac;
        auto* arp_hdr = (Arphdr*) (pac + sizeof(Ethhdr));
        if (memcmp(eth_hdr->ether_dhost, this->client.mac, ETH_ALEN) == 0)
            if (ntohl(arp_hdr->ea_hdr.ar_op) == ARPOP_REPLY)
                if (memcmp(&arp_hdr->arp_spa, ip_from, 4) == 0) {
                    delete pac;
                    return true;
                }
    }
    delete pac;
    return false;
}

int DHCP_CLIENT::DHCP_Send_Decline() {
    if (this->DHCPPACK_buff.empty()) {
        this->Error = DHCPACK_BUFF_IS_EMPTY;
        return EXIT_FAILURE;
    }

    char* DHCPACK_packet = this->DHCPPACK_buff.front();
    auto* dhcppack = (Dhcp_packet *) (DHCPACK_packet + this->offset.goto_dhcppac);
    char* packet = this->get_DHCPDECLINE_packet(dhcppack->yiaddr.s_addr);
    if (sendto(this->sock, packet, MAX_SIZE_PACKET, 0, (struct sockaddr*) &this->addr_ll, sizeof(struct sockaddr_ll)) < 0) {
        this->Error = SEND_ERROR;
        delete packet;
        return EXIT_FAILURE;
    }
    delete packet;
    return EXIT_SUCCESS;
}

char* DHCP_CLIENT::get_DHCPDECLINE_packet(in_addr_t ip) {
    char* packet = new char[MAX_SIZE_PACKET];
    memset(packet, 0, MAX_SIZE_PACKET);

    auto* eth_hdr = (Ethhdr*) packet;
    auto* ip_hdr = (Iphdr*) (packet + this->offset.goto_iphdr);
    auto* udp_hdr = (Udphdr*) (packet + this->offset.goto_udphdr);
    auto* Dhcp_pack = (Dhcp_packet*) (packet + this->offset.goto_dhcppac);

    Fill_eth_hdr(eth_hdr);
    Fill_ip_hdr(ip_hdr);
    Fill_udp_hdr(udp_hdr);
    Fill_base_dhcp_pac(Dhcp_pack);
    Dhcp_pack->yiaddr.s_addr = ip;
    uint32_t cur = 0;
    char option = DHCPDECLINE;
    cur = Fill_dhcp_options(Dhcp_pack, cur, DHCP_OPTION_MESSAGE_TYPE, 1, &option);
    cur = Fill_dhcp_options(Dhcp_pack, cur, DHCP_OPTION_REQUESTED_ADDRESS, IP_ALEN, reinterpret_cast<char*>(&ip));
    Dhcp_pack->options[cur] = static_cast<char>(DHCP_OPTION_END);

    Ip_csum(ip_hdr);
    Udp_csum(ip_hdr, udp_hdr);

    return packet;
}

int DHCP_CLIENT::DHCP_Binding() {
    if (this->DHCPPACK_buff.empty()) {
        this->Error = DHCPACK_BUFF_IS_EMPTY;
        return EXIT_FAILURE;
    }

    char* DHCPACK_packet = this->DHCPPACK_buff.front();
    auto* dhcppack = (Dhcp_packet *) (DHCPACK_packet + this->offset.goto_dhcppac);
    int32_t cur = Find_DHCP_option(dhcppack, DHCP_OPTION_LEASE_TIME);
    if (cur == -1) {
        this->Error = DHCP_SERVER_NO_SEND_LEASE_TIME;
        return EXIT_FAILURE;
    }
    uint32_t local_lease_time;
    memcpy(&local_lease_time, &dhcppack->options[cur + 2], 4);
    local_lease_time = htonl(local_lease_time);
    this->timing.lease_time = 30; //local_lease_time;
    this->timing.renewal_time = this->timing.lease_time / 2;
    this->timing.rebinding_time = this->timing.lease_time * 0.875;

    double time_now = this->get_time();

    this->timeout.renewal_timeout = this->timing.renewal_time - (time_now - this->timing.time_ACK) + (random() % 10 + 1);
    this->timeout.rebinding_timeout = this->timing.rebinding_time + (random() % 10 + 1);
    this->timeout.lease_timeout = this->timing.lease_time + 20;
    this->DHCP_Show_Settings();
    sleep(static_cast<unsigned int>(this->timeout.renewal_timeout));
    return EXIT_SUCCESS;
}

double DHCP_CLIENT::get_time() {
    struct timeval t;
    gettimeofday(&t, NULL);
    return (double) t.tv_sec + (double) t.tv_usec * 1E-6;
}

int DHCP_CLIENT::DHCP_Renewal() {
    if(this->DHCPPACK_buff.empty()) {
        this->Error = DHCPACK_BUFF_IS_EMPTY;
        return EXIT_FAILURE;
    }
    char* DHCPACK_packet = this->DHCPPACK_buff.front();
    Dhcp_packet* dhcpack = (Dhcp_packet*) (DHCPACK_packet + this->offset.goto_dhcppac);

    while ((this->get_time() - this->timing.time_ACK) < this->timeout.rebinding_timeout) {
        char* REQUEST = this->get_Renewal_DHCPREQUEST_packet(dhcpack->siaddr.s_addr, dhcpack->yiaddr.s_addr);
        if (sendto(this->sock, REQUEST, MAX_SIZE_PACKET, 0, (struct sockaddr*) &this->addr_ll, sizeof(struct sockaddr_ll)) < 0) {
            this->Error = SEND_ERROR;
            delete REQUEST;
            return EXIT_FAILURE;
        }
        delete REQUEST;

        char* ACK = this->get_DHCP_packet();
        if (!ACK) {
            continue;
        }
        Dhcp_packet* dhcp_pack = (Dhcp_packet*) (ACK + this->offset.goto_dhcppac);
        int cur = Find_DHCP_option(dhcp_pack, DHCP_OPTION_MESSAGE_TYPE);
        if (cur != -1) {
            if (dhcp_pack->options[cur + 2] == DHCPACK) {
                this->timing.time_ACK = this->get_time();
                this->DHCPPACK_buff.pop();
                this->DHCPPACK_buff.push(ACK);
                return EXIT_SUCCESS;
            } else if (dhcp_pack->options[cur + 2] == DHCPNACK) {
                delete ACK;
                return GOTO_INIT_STATE;
            } else {
                delete ACK;
                continue;
            }
        }
    }
    return GOTO_REASSOCIATION_STATE;
}

char* DHCP_CLIENT::get_DHCP_packet() {
    uint32_t socklen;
    struct sockaddr_in recv_addrin {};
    memset(&recv_addrin, 0, sizeof(struct sockaddr_in));
    ssize_t bytes_read;
    size_t wait = this->select_timeout;
    auto* pack = new char[MAX_SIZE_PACKET];
    while (wait--) {
        bytes_read = recvfrom(this->sock, pack, MAX_SIZE_PACKET, 0, (struct sockaddr*) &recv_addrin, &socklen);
        if (bytes_read == EAGAIN || bytes_read <= 0) {
            continue;
        }
        auto* eth_hdr = (Ethhdr*) pack;
        auto* udp_hdr = (Udphdr*) (pack + this->offset.goto_udphdr);
        auto* dhcp_pack = (Dhcp_packet*) (pack + this->offset.goto_dhcppac);
        if (ntohs(udp_hdr->dest) == this->client.port) {
            if (memcmp(eth_hdr->ether_dhost, this->client.mac, ETH_ALEN) == 0 || memcmp(eth_hdr->ether_dhost, this->servers.mac, ETH_ALEN) == 0) {
                if (ntohl(dhcp_pack->xid) == this->packet_xid) {
                    return pack;
                }
            }
        }
    }
    return nullptr;
}

char* DHCP_CLIENT::get_Renewal_DHCPREQUEST_packet(in_addr_t server_ip, in_addr_t my_ip) {
    char* packet = new char[MAX_SIZE_PACKET];
    memset(packet, 0, MAX_SIZE_PACKET);
    auto* eth_hdr = (Ethhdr*) packet;
    auto* ip_hdr = (Iphdr*) (packet + this->offset.goto_iphdr);
    auto* udp_hdr = (Udphdr*) (packet + this->offset.goto_udphdr);
    auto* Dhcp_pack = (Dhcp_packet*) (packet + this->offset.goto_dhcppac);


    Fill_eth_hdr(eth_hdr);
    Fill_ip_hdr(ip_hdr);
    memcpy(&ip_hdr->daddr, &server_ip, IP_ALEN);
    memcpy(&ip_hdr->saddr, &my_ip, IP_ALEN);
    Fill_udp_hdr(udp_hdr);
    Fill_base_dhcp_pac(Dhcp_pack);
    Dhcp_pack->ciaddr.s_addr = my_ip;

    uint32_t cur = 0;
    char option = DHCPREQUEST;
    cur = Fill_dhcp_options(Dhcp_pack, cur, DHCP_OPTION_MESSAGE_TYPE, 1, &option);
    cur = Fill_dhcp_options(Dhcp_pack, cur, DHCP_OPTION_HOST_NAME, static_cast<uint8_t>(strlen(this->hostname)), this->hostname);

    unsigned char parameter_request_list[16];
    parameter_request_list[0] = 1;      // Subnet Mask
    parameter_request_list[1] = DHCP_OPTION_BROADCAST_ADDRESS;     // Broadcast Address
    parameter_request_list[2] = 2;      // Time Offset
    parameter_request_list[3] = 3;      // Router
    parameter_request_list[4] = 15;     // Domain Name
    parameter_request_list[5] = 6;      // Domain Name Server
    parameter_request_list[6] = 119;    // Domain Search
    parameter_request_list[7] = DHCP_OPTION_HOST_NAME;     // Host Name
    parameter_request_list[8] = 44;     // NetBIOS over TCP/IP Name Server
    parameter_request_list[9] = 47;     // NetBIOS over TCP/IP Scope
    parameter_request_list[10] = 26;    // Interface MTU
    parameter_request_list[11] = 121;   // Classless Static Route
    parameter_request_list[12] = 42;    // Network Time Protocol Servers
    parameter_request_list[13] = 249;   // Private/Classless Static Route (Microsoft)
    parameter_request_list[14] = 33;    // Static Route
    parameter_request_list[15] = 252;   // Private/Proxy autodiscovery

    cur = Fill_dhcp_options(Dhcp_pack, cur, DHCP_OPTION_REQUEST_LIST, 16, reinterpret_cast<char*>(parameter_request_list));
    Dhcp_pack->options[cur] = static_cast<char>(DHCP_OPTION_END);

    Ip_csum(ip_hdr);
    Udp_csum(ip_hdr, udp_hdr);
    return packet;
}

int DHCP_CLIENT::DHCP_Reassociation() {
    if(this->DHCPPACK_buff.empty()) {
        this->Error = DHCPACK_BUFF_IS_EMPTY;
        return EXIT_FAILURE;
    }
    char* DHCPACK_packet = this->DHCPPACK_buff.front();
    Dhcp_packet* dhcpack = (Dhcp_packet*) (DHCPACK_packet + this->offset.goto_dhcppac);
    while ((this->get_time() - this->timing.time_ACK) < this->timeout.lease_timeout) {
        char* REQUEST = this->get_DHCPREQUEST_packet(dhcpack->yiaddr);
        if (sendto(this->sock, REQUEST, MAX_SIZE_PACKET, 0, (struct sockaddr*) &this->addr_ll, sizeof(struct sockaddr_ll)) < 0) {
            this->Error = SEND_ERROR;
            delete REQUEST;
            return EXIT_FAILURE;
        }
        delete REQUEST;

        char* ACK = this->get_DHCP_packet();
        if (!ACK) {
            continue;
        }
        Dhcp_packet* dhcp_pack = (Dhcp_packet*) (ACK + this->offset.goto_dhcppac);
        int cur = Find_DHCP_option(dhcp_pack, DHCP_OPTION_MESSAGE_TYPE);
        if (cur != -1) {
            if (dhcp_pack->options[cur + 2] == DHCPACK) {
                this->timing.time_ACK = this->get_time();
                this->DHCPPACK_buff.pop();
                this->DHCPPACK_buff.push(ACK);
                return EXIT_SUCCESS;
            } else if (dhcp_pack->options[cur + 2] == DHCPNACK) {
                delete ACK;
                return GOTO_INIT_STATE;
            } else {
                delete ACK;
                continue;
            }
        }
    }
    return GOTO_INIT_STATE;
}

void DHCP_CLIENT::DHCP_Show_Settings() {
    if(this->DHCPPACK_buff.empty()) {
        this->Error = DHCPACK_BUFF_IS_EMPTY;
        return;
    }
    char* DHCPACK_packet = this->DHCPPACK_buff.front();
    Dhcp_packet* dhcpack = (Dhcp_packet*) (DHCPACK_packet + this->offset.goto_dhcppac);
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(dhcpack->yiaddr), str, INET_ADDRSTRLEN);
    std::cout << "You IP Address: " << str << std::endl;
}
