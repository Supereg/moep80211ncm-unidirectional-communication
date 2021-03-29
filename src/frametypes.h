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
	/**
	 * The session_id
	 */
	struct session_id session_id;
	// The generation sequence number of the generation this packet is sent for.
	/**
	 * The sequence number of the generation a given coded packet
	 * stems from or is addressed to.
	 * For ACK frames this value is zero and has no meaning.
	 */
	u16 sequence_number;
	/**
	 * The smallest sequence number of the current generation window.
	 */
	u16 window_id;
	/**
	 * The Galois field type used.
	 */
	u8 gf : 2;
	/**
	 * Flag to determine if the frame payload is an acknowledgment.
	 * If so, the payload is to be interpreted as an array
	 * of `struct ack_payload`.
	 */
	u8 ack : 1;
	/**
	 * The generation window size.
	 */
	u8 window_size : 5;
} __attribute__((packed));

struct ncm_hdr_bcast {
	struct moep_hdr_ext hdr;
	u32 id;
} __attribute__((packed));

#endif //__FRAMETYPES_H
