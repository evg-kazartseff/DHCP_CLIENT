//
// Created by evgenii on 25.03.18.
//

#include "FSM.h"

int FSM::getState() const {
    return state;
}

void FSM::setState(int state) {
    FSM::state = state;
}
