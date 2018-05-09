//
// Created by evgenii on 21.03.18.
//

#include <getopt.h>
#include <net/if.h>
#include <cstring>
#include <zconf.h>
#include <random>
#include "DHCP_CLIENT.h"
#include "FSM.h"

void print_help(char* name_p) {
    std::cout << "Use " << name_p << " -i [interface]" << std::endl;
}

int main(int argc, char** argv) {
    if (argc == 1) {
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }
    char ifname[IFNAMSIZ];
    int opt;
    do {
        opt = getopt(argc, argv, "h?i:");
        switch (opt) {
            case 'i':
                memcpy(ifname, optarg, IFNAMSIZ);
                break;
            case '?':
            case 'h':
                print_help(argv[0]);
                break;
            default:
                break;
        }
    } while (opt != -1);
    DHCP_CLIENT* dhcp_client = new DHCP_CLIENT(ifname);
    FSM* fsm = new FSM();
    fsm->setState(STATE_INIT);
    bool run = true;
    while (run) {
        switch (fsm->getState()) {
            case STATE_INIT:
                if (dhcp_client->DHCP_Init() == EXIT_SUCCESS)
                    fsm->setState(STATE_SELECT);
                else
                    fsm->setState(STATE_ERR);
                break;
            case STATE_SELECT:
                if (dhcp_client->DHCP_Select() == EXIT_SUCCESS)
                    fsm->setState(STATE_REQUEST);
                else
                    fsm->setState(STATE_ERR);
                break;
            case STATE_REQUEST:
                dhcp_client->DHCP_Request();
                fsm->setState(STATE_ERR);
            case STATE_ERR:
                dhcp_client->DHCP_Error_Hadler();
                run = false;
                break;
            default:
                run = false;
                break;
        }
    }
    return 0;
}