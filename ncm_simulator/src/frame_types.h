//
// Created by Andreas Bauer on 10.03.21.
//

// TODO this file is to be merged with the frametypes.h in the ncm module!

#ifndef MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_FRAME_TYPES_H
#define MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_FRAME_TYPES_H

#include "global.h"
#include "session.h"

#include <assert.h>

#include <moepcommon/util.h>

#include <moep/types.h>
#include <moep/frame.h>
#include <moep/moep_hdr_ext.h>
#include <moep/modules/ieee8023.h>

enum headertypes {
    NCM_HDR_BIDIRECTIONAL_CODED = 0x21, // replacing "legacy" NCM_HDR_CODED (ncm_hdr_coded)
    NCM_HDR_UNIDIRECTIONAL_CODED = 0x024, // new hdr type
};

enum frametypes {
    NCM_DATA_UNIDIRECTIONAL = 4,
};

/**
 * Header type NCM_HDR_UNIDIRECTIONAL_CODED
 */
struct ncm_hdr_unidirectional_coded {
    struct moep_hdr_ext hdr;
    u8 session_id[2 * IEEE80211_ALEN];
    u16 sequence_number; // TODO document, no meaning for ack frames
    u16 window_id;
    u8 gf:2;
    u8 ack:1;
    u8 window_size:5;
};


/*
 * Below functions are sketches of what will need to be added to the ncm module when integrating
 * the new unidirectional session system.
 * Those functions handle assembly and disassembly of moep frames.
 * TODO the jitter suppression module must be inserted at on this level
 * TODO remove this note once integrated.
 */

int ncm_session_encoder_add(session_t* session, moep_frame_t frame) {
    ether_header_t *ether_header;
    u8 *payload;
    size_t length;

    ether_header = moep_frame_ieee8023_hdr(frame);
    if (ether_header == NULL) {
        LOG_SESSION(LOG_WARNING, session, "Failed to retrieve ether_header for source frame, discarding...");
        return -1;
    }

    payload = moep_frame_get_payload(frame, &length);
    if (payload == NULL) {
        LOG_SESSION(LOG_WARNING, session, "Source frame didn't have an associated payload, ignoring...");
        return -1;
    }

    return session_encoder_add(session, buffer, length);
}

int ncm_session_decoder_add(session_t* session, moep_frame_t frame) {
    u8* payload;
    size_t payload_length;

    payload = moep_frame_get_payload(frame, &payload_length);
    if (payload == NULL) {
        LOG_SESSION(LOG_WARNING, session, "Received coded frame didn't have an associated payload. Discarding ...");
        return -1;
    }

    return session_decoder_add(session, payload, payload_length, true);
}

int set_coded_header(struct ncm_hdr_unidirectional_coded* coded_header, coded_packet_metadata_t* metadata) {
    memcpy(coded_header->session_id, metadata->sid, sizeof(struct session_id));
    coded_header->sequence_number = metadata->generation_sequence;
    coded_header->window_id = metadata->window_id;
    coded_header->gf = metadata->gf;
    coded_header->ack = metadata->ack;
    coded_header->window_size = metadata->window_size;
}

int tx_encoded_frame(struct session_subsystem_context* context, session_t* session, coded_packet_metadata_t* metadata, u8* payload, size_t length) {
    session_id* session_id;
    moep_dev_t device = NULL; // TODO need the pointer to the device
    moep_frame_t frame;
    struct ncm_hdr_unidirectional_coded* coded_header;
    struct moep80211_hdr *hdr;

    session_id = session_get_id(session);

    frame = moep_dev_frame_create(device);

    coded_header = (struct ncm_hdr_unidirectional_coded*) moep_frame_add_moep_hdr_ext(
        frame,
        (enum moep_hdr_type) NCM_HDR_UNIDIRECTIONAL_CODED,
        sizeof(struct ncm_hdr_unidirectional_coded));
    set_coded_header(coded_header, metadata);

    if (moep_frame_set_payload(frame, payload, length) == NULL) {
        LOG_SESSION(LOG_WARNING, session, "Failed to set frame payload of next encoded frame: %s", strerror(errno));
        moep_frame_destroy(frame);
        return -1;
    }

    hdr = moep_frame_moep80211_hdr(frame);
    if (hdr == NULL) {
        LOG_SESSION(LOG_WARNING, session, "Failed to init moep802211 hdr of next encoded frame: %s", strerror(errno));
        moep_frame_destroy(frame);
        return -1;
    }

    memset(hdr->ra, 0xff, IEEE80211_ALEN);
    memcpy(hdr->ta, context->local_address, IEEE80211_ALEN);

    // TODO send out via the device

    moep_frame_destroy(frame);

    return 0;
}

int tx_decoded_frame(struct session_subsystem_context* context, session_t* session, u16 ether_type, u8* payload, size_t length) {
    session_id* session_id;
    moep_frame_t  frame;
    struct ether_header* ether_header;

    session_id = session_get_id(session);

    frame = moep_frame_ieee8023_create();
    if (frame == NULL) {
        LOG_SESSION(LOG_WARNING, session, "Failed to init ieee8023 frame of decoded frame: %s", strerror(errno));
        return -1;
    }

    ether_header = moep_frame_ieee8023_hdr(frame);
    if (ether_header == NULL) {
        LOG_SESSION(LOG_WARNING, session, "Failed to init ether_header on ieee8023 frame: %s", strerror(errno));
        return -1;
    }

    ether_header->ether_type = ether_type;
    memcpy(ether_header->ether_shost, session_id->source_address, IEEE80211_ALEN);
    memcpy(ether_header->ether_dhost, session_id->destination_address, IEEE80211_ALEN);

    moep_frame_set_payload(frame, payload, length);

    // TODO jsm module?

    // TODO send frame back to the OS

    moep_frame_destroy(frame);

    return 0;
}

#endif //MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_FRAME_TYPES_H
