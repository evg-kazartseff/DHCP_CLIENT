//
// Created by evgenii on 25.03.18.
//

#ifndef DHCP_CLIENT_FSM_H
#define DHCP_CLIENT_FSM_H

enum states {
    STATE_INIT,

};

class FSM {
private:
    int state;
public:
    FSM() = default;
    int getState() const;
    void setState(int state);
};

#endif //DHCP_CLIENT_FSM_H
