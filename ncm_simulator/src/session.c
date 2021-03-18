//
// Created by Andreas Bauer on 22.02.21.
//

#include "global.h"
#include "session.h"

#include <assert.h>

#include <moepcommon/list.h>
#include <moepcommon/util.h>

#include "generation.h"

/**
 * Defines any state of a given session.
 */
struct session {
    struct list_head list;

    /**
     * The associated `session_subsystem_context_t` this session was added to.
     */
    session_subsystem_context_t* context;

    /**
     * The `session_id` uniquely identifying the given session!
     */
    session_id session_id;

    /**
     * The `SESSION_TYPE` of the given session.
     */
    enum SESSION_TYPE type;

    // TODO session state?

    // TODO session destroy timer!

    /**
     * Linked list, containing all `generation_t`s associated with the given session.
     */
    struct list_head generations_list;
};

void session_list_free(session_subsystem_context_t* context); // forward declaration used in session_subsystem_close()
int session_transmit_next_encoded_frame(session_t* session); // forward declaration use in session_encoder_add()


session_subsystem_context_t* session_subsystem_init(
    int generation_size,
    int generation_window_size,
    enum MOEPGF_TYPE moepgf_type,
    u8* hw_address,
    encoded_payload_callback rtx_callback,
    decoded_payload_callback os_callback) {
    struct session_subsystem_context* context;

    assert(hw_address != NULL && "hw_address pointer can't be NULL pointer!");
    assert(rtx_callback != NULL && "rtx_callback pointer can't be NULL pointer!");
    assert(os_callback != NULL && "os_callback pointer can't be NULL pointer!");

    context = calloc(1, sizeof(session_subsystem_context_t));
    if (context == NULL) {
        DIE("Failed session_subsystem_init() to allocated a `session_subsystem_context_t`!");
    }

    *(int*) &context->generation_size = generation_size;
    *(int*) &context->generation_window_size = generation_window_size;
    *(enum MOEPGF_TYPE*) &context->moepgf_type = moepgf_type;

    memcpy(context->local_address, hw_address, IEEE80211_ALEN);

    context->rtx_callback = rtx_callback;
    context->os_callback = os_callback;

    INIT_LIST_HEAD(&context->sessions_list);

    return context;
}

void session_subsystem_close(session_subsystem_context_t* context) {
    session_list_free(context);

    free(context);
}



/**
 * Determines the `SESSION_TYPE` for the given tuple of source and destination mac addresses,
 * by comparing them to the local hardware address.
 * Parameters `ether_source_host` and `ether_destination_host` must not be equal!
 *
 * @param ether_source_host - The source mac address.
 * @param ether_destination_host - The destination mac address.
 * @return Returns the `SESSION_TYPE` depending of the result of comparisons against the local hardware address.
 */
enum SESSION_TYPE session_type_derived(session_subsystem_context_t* context, const u8* ether_source_host, const u8 *ether_destination_host) {
    // Seemingly the ncm module is not built to expect matching addresses
    assert(memcmp(ether_source_host, ether_destination_host, IEEE80211_ALEN) != 0);

    if (memcmp(context->local_address, ether_source_host, IEEE80211_ALEN) == 0) {
        return SOURCE;
    } else if (memcmp(context->local_address, ether_destination_host, IEEE80211_ALEN) == 0) {
        return DESTINATION;
    } else {
        return INTERMEDIATE;
    }
}

session_t* session_find(session_subsystem_context_t* context, const u8* ether_source_host, const u8 *ether_destination_host) {
    struct session* session;
    enum SESSION_TYPE session_type;

    session_type = session_type_derived(context, ether_source_host, ether_destination_host);

    list_for_each_entry(session, &context->sessions_list, list) {
        if (memcmp(session->session_id.source_address, ether_source_host, IEEE80211_ALEN) == 0
            && memcmp(session->session_id.destination_address, ether_destination_host, IEEE80211_ALEN) == 0
            && session->type == session_type) {
            // the additional type check above, allows us to have the SOURCE=DESTINATION
            // Not really supported by the ncm code itself (as we ignored packets from our own)
            // but helps with some flexibility in our unit tests.
            return session;
        }
    }

    return NULL;
}

session_t* session_register(session_subsystem_context_t* context, const u8* ether_source_host, const u8 *ether_destination_host) {
    enum SESSION_TYPE session_type;
    struct session* session;

    session_type = session_type_derived(context, ether_source_host, ether_destination_host);
    session = session_find(context, ether_source_host, ether_destination_host);

    if (session != NULL) {
        assert(session->type == session_type);
        return session;
    }

    session = calloc(1, sizeof(struct session));
    if (session == NULL) {
        DIE("Failed to calloc() session: %s", strerror(errno));
    }

    session->context = context;

    memcpy(session->session_id.source_address, ether_source_host, IEEE80211_ALEN);
    memcpy(session->session_id.destination_address, ether_destination_host, IEEE80211_ALEN);

    session->type = session_type;

    INIT_LIST_HEAD(&session->generations_list);

    for (int i = 0; i < context->generation_window_size; i++) {
        generation_init(
            session,
            &session->generations_list,
            session_type,
            context->moepgf_type,
            context->generation_size,
            MAX_PDU_SIZE,
            MEMORY_ALIGNMENT);
    }

    list_add(&session->list, &context->sessions_list);

    LOG_SESSION(LOG_INFO, session, "New session created");

    return session;
}

session_id* session_get_id(session_t* session) {
    return &session->session_id;
}

void session_free(session_t* session) {
    list_del(&session->list);

    generation_list_free(&session->generations_list);

    // TODO timeout delete

    // TODO potential logging file unlink (do we want/need to [re]implement that?)

    LOG_SESSION(LOG_INFO, session, "Session destroyed");

    free(session);
}

/**
 * Frees up the global session list.
 */
void session_list_free(session_subsystem_context_t* context) {
    session_t *current, *tmp;

    list_for_each_entry_safe(current, tmp, &context->sessions_list, list) {
        session_free(current);
    }
}

int session_encoder_add(session_t* session, u16 ether_type, u8* payload, size_t payload_length) {
    NCM_GENERATION_STATUS status;
    static u8 buffer[MAX_PDU_SIZE] = {0};
    size_t buffer_length;
    // see docs of `coded_payload_metadata`
    struct coded_payload_metadata* metadata;

    assert(session->type == SOURCE && "Only a SOURCE session can add source frames!");

    // 1. prepend our frame buffer with the `coded_payload_metadata` metadata
    //   to preserve ether type and length information in our linear combinations of packets

    buffer_length = payload_length + sizeof(struct coded_payload_metadata);
    // TODO we later need to transport the coding vectors + the buffer in a single PDU,
    //   thus this check would somehow need to account for that
    //   (the check will be repeated later [with also checking coding coefficients], but is probably better to catch that early?
    if (buffer_length > MAX_PDU_SIZE) {
        LOG_SESSION(LOG_WARNING, session, "Received a source frame which is bigger than the maximum of %lu bytes",
                    (MAX_PDU_SIZE - sizeof(struct coded_payload_metadata)));
        return -1;
    }

    metadata = (void*) buffer;
    metadata->payload_type = htole16(be16toh(ether_type)); // iee 80211 is LE

    memcpy(buffer + sizeof(struct coded_payload_metadata), payload, payload_length);


    // 2. add the buffer (with prepended `coded_payload_metadata`) to the next available generation in our list.
    status = generation_list_encoder_add(&session->generations_list, buffer, buffer_length);
    if (status != GENERATION_STATUS_SUCCESS) {
        // most probably happens when our generations are full and we can't store any further frames.
        LOG_SESSION(LOG_WARNING, session, "Failed to store source frame(%d), discarding...", status);
        return -1;
    }

    // 3. create a new encoded frame and transmit it over radios (TODO replace with timer based solution)
    session_transmit_next_encoded_frame(session);

    return 0;
}

void session_check_for_decoded_frames(session_t* session) {
    NCM_GENERATION_STATUS  status;
    static u8 buffer[MAX_PDU_SIZE] = {0};
    size_t buffer_length;

    struct coded_payload_metadata* metadata;
    u8* payload;
    size_t payload_length;

    // TODO sending back to OS is only valid for session type of DESTINATION.
    //   forwarders have to encode the frames at this point (and send them out), so forwarders are currently unsupported!
    assert(session->type == DESTINATION && "forwards are currently unsupported");

    for (;;) {
        buffer_length = 0;
        status = generation_list_next_decoded(&session->generations_list, sizeof(buffer), buffer, &buffer_length);

        if (status == GENERATION_FULLY_TRAVERSED || status == GENERATION_NOT_YET_DECODABLE) {
            break;
        } else if (status != GENERATION_STATUS_SUCCESS) {
            LOG_SESSION(LOG_WARNING, session, "Found unexpected error when trying to retrieve next decoded payload: %d", status);
            break;
        }

        // every encoded frame is prepended with a `struct coded_payload_metadata`
        // below code is undoing this, and pulling out all the metadata information.

        metadata = (void*) buffer;
        payload = buffer + sizeof(struct coded_payload_metadata);
        payload_length = buffer_length - sizeof(struct coded_payload_metadata);

        // ieee 80211 is LE, while ieee 8023 is BE
        u16 ether_type = htobe16(le16toh(metadata->payload_type));

        session->context->os_callback(session->context, session, ether_type, payload, payload_length);
    }

    // TODO reset future session destroy timeout
}

int session_decoder_add(session_t* session, coded_packet_metadata_t* metadata, u8* payload, size_t length, bool forward_os) { // TODO replace forward_os (only for internal testing)
    NCM_GENERATION_STATUS status;

    if (metadata->ack) {
        assert(session->type == SOURCE);
        status = parse_ack_payload(&session->generations_list, (ack_payload_t *) payload);
        if (status != GENERATION_STATUS_SUCCESS) {
            return -1;
        }
    } else {
        assert(session->type == DESTINATION || session->type == INTERMEDIATE);
        status = generation_list_decoder_add_decoded(&session->generations_list, metadata, payload, length);
        if (status != GENERATION_STATUS_SUCCESS) {
            return -1;
        }

        if (!forward_os) {
            return 0;
        }

        session_check_for_decoded_frames(session);   
    }

    /**
     * decoding of coded packet or parsing of ack frame has been successful
     * we need to call advance_generation to check if any of the generations
     * is now full for sender or receiver side
     */
    (void) generation_list_advance(&session->generations_list);
    return 0;
}

/**
 * generates the metadata values for a given session
 * @param metadata pointer to metadata struct that is to be filled out
 * @param session pointer to current session
 * @param ack flag if acknowlegment flag is to be set
 */
static void session_metadata(coded_packet_metadata_t* metadata, session_t* session, u8 ack) {
    metadata->sid = *(session_get_id(session));
    metadata->generation_sequence = 0; // this will be set by generation_list_next_encoded_frame afterwards
    metadata->smallest_generation_sequence = get_first_generation_number(&session->generations_list);
    metadata->gf = GF;
    metadata->ack = ack;
    metadata->window_size = GENERATION_WINDOW_SIZE;
}

int session_transmit_next_encoded_frame(session_t* session) {
    NCM_GENERATION_STATUS status;
    static u8 buffer[MAX_PDU_SIZE] = {0};
    static coded_packet_metadata_t metadata;
    size_t length;

    // TODO the current implementation has a "encode" timer for **Every** generation,
    //  does this have any real reason? If not we can reduce "management overhead"
    //  by having **one** "encode" timer for every session, iterating over all generations
    //  checking what has to be sent out.

    session_metadata(&metadata, session, 0);

    status = generation_list_next_encoded_frame(&session->generations_list, sizeof(buffer), &metadata, buffer, &length);

    if (status != GENERATION_STATUS_SUCCESS) {
        return -1;
    }

    session->context->rtx_callback(session->context, session, &metadata, buffer, length);

    return 0;
}

int session_transmit_ack_frame(session_t* session) {
    static ack_payload_t payload[GENERATION_WINDOW_SIZE] = {0};
    static coded_packet_metadata_t metadata;

    get_generation_feedback(&session->generations_list, payload);
    
    session_metadata(&metadata, session, 1);

    session->context->rtx_callback(session->context, session, &metadata, (u8 *) payload, (sizeof(ack_payload_t) * GENERATION_WINDOW_SIZE));

    return 0;
}
