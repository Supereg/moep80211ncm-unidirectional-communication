//
// Created by Andreas Bauer on 03.03.21.
//

#ifndef MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_GLOBAL_H
#define MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_GLOBAL_H

#define MEMORY_ALIGNMENT 32
#define MAX_PDU_SIZE 64 // default is 8192 GENERATION_MAX_PDU_SIZE

#define GENERATION_SIZE 4 // default is 128 GENERATION_SIZE // TODO we can half the default 128 size, as we previously used that for two directions and now only need one
#define GENERATION_WINDOW_SIZE 2

#define IEEE80211_ALEN 6 // TODO params.h (ncm defines it themselves, somehow find a "unififed" place for this)

#define GF MOEPGF16

#endif //MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_GLOBAL_H
