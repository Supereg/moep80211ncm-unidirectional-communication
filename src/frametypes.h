#ifndef __FRAMETYPES_H
#define __FRAMETYPES_H

#include <moep/system.h>
#include <moep/types.h>
#include <moep/ieee80211_addr.h>

#include "generation.h"

enum headertypes {
	NCM_HDR_DATA = MOEP_HDR_VENDOR_MIN, // 0x20
	NCM_HDR_CODED,
	NCM_HDR_BCAST,
	NCM_HDR_BEACON,
	NCM_HDR_UNIDIRECTIONAL_CODED, // new unidir hdr type
	NCM_HDR_INVALID = MOEP_HDR_COUNT - 1
};

enum frametypes {
	NCM_DATA = 0,
	NCM_CODED,
	NCM_CODED_UNIDIR,
	NCM_BEACON,
	NCM_INVALID,
};

struct ncm_hdr_beacon {
	struct moep_hdr_ext hdr;
} __attribute__((packed));

struct ncm_beacon_payload {
	u8 mac[IEEE80211_ALEN];
	u16 p;
	u16 q;
} __attribute__((packed));

/**
 * Header type NCM_HDR_UNIDIRECTIONAL_CODED
 */
struct ncm_hdr_unidirectional_coded {
	struct moep_hdr_ext hdr;
	struct session_id session_id;
	// The generation sequence number of the generation this packet is sent for.
	u16 sequence_number;
	// sequence number of the first generation in the window
	u16 window_id;
	u8 gf : 2;
	// acknowledgment flag
	u8 ack : 1;
	u8 window_size : 5;
};

struct ncm_hdr_bcast {
	struct moep_hdr_ext hdr;
	u32 id;
} __attribute__((packed));

#endif //__FRAMETYPES_H
