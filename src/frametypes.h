#ifndef __FRAMETYPES_H
#define __FRAMETYPES_H

#include <moep/system.h>
#include <moep/types.h>
#include <moep/ieee80211_addr.h>

#include "generation.h"

enum headertypes {
	NCM_HDR_DATA	= MOEP_HDR_VENDOR_MIN, // 0x20
	NCM_HDR_CODED, // 0x21
	NCM_HDR_BCAST, // 0x22
	NCM_HDR_BEACON, // 0x23
	NCM_HDR_INVALID	= MOEP_HDR_COUNT-1
};

enum frametypes {
	NCM_DATA = 0,
	NCM_CODED,
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
  Bware: the coding header is a variable-length header, depending on the galois
  field and generation size.
  */
struct ncm_hdr_coded {
	struct moep_hdr_ext hdr;
	/// The session id consisting of sender and receiver mac address
    /// (appended according to the definition of master and slave).
	u8 sid[2*IEEE80211_ALEN];
	/// The galois field type used. See `MOEPGF_TYPE`.
	u8 gf:2;
    /// Defines the generation window size. So the count of our generation list for the given session.
	u8 window_size:6;
	/// The generation sequence number of the generation this packet is sent for.
	/// See `generation_seq`.
	u16 seq;
	/// Corresponds to the generation sequence number of the first generation
	/// of the generation list for the given session. See `generation_lseq`.
	u16 lseq;
	/// One `generation_feedback` for every generation in our generation list.
	/// Meaning the array equals to `window_size`.
	struct generation_feedback fb[0];
} __attribute__((packed));

struct ncm_hdr_bcast {
	struct moep_hdr_ext hdr;
	u32 id;
} __attribute__((packed));

#endif //__FRAMETYPES_H
