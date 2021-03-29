//
// Created by Andreas Bauer on 23.03.21.
//

#ifndef MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_CHECK_SESSION_H
#define MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_CHECK_SESSION_H

#include "moepcommon/list.h"
#include "../src/session.h"

struct list_head*
session_generation_list(session_t* session);

#endif //MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_CHECK_SESSION_H
