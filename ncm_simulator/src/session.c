//
// Created by Andreas Bauer on 22.02.21.
//

#include "global.h"
#include "session.h"

#include <assert.h>

#include <moepcommon/list.h>
#include <moepcommon/util.h>

#include "generation.h"

#define LOG_SESSION(loglevel, session, message, ...) \
do { \
    u8* source_address = session->session_id.source_address; \
    u8* destination_address = session->session_id.destination_address; \
    LOG(loglevel, message" (source: %02x:%02x:%02x:%02x:%02x:%02x, destination: %02x:%02x:%02x:%02x:%02x:%02x)", \
        ## __VA_ARGS__ , \
        source_address[0], source_address[1], source_address[2], \
        source_address[3], source_address[4], source_address[5], \
        destination_address[0], destination_address[1], destination_address[2], \
        destination_address[3], destination_address[4], destination_address[5]); \
} while (0)

/**
 * Asserts that the user did call `init_session_subsystem` (and thus the `session_context` context is set).
 */
#define ASSERT_SESSION_CONTEXT() \
assert(session_context != NULL && "session_subsystem_context was not initialized. init_session_subsystem() must be called first!")

/**
 * Calls `ASSERT_SESSION_CONTEXT` to ensure that `init_session_subsystem` was called
 * to initialize a valid `session_subsystem_context` is present.
 * The `property` defines a property of the `session_subsystem_context` struct
 * and asserts, that it is not equal to what is passed into `non_equality_check`.
 */
#define ASSERT_SESSION_CONTEXT_PROPERTY(property, non_equality_check) \
ASSERT_SESSION_CONTEXT(); \
assert(session_context->property != (non_equality_check) && "session_subsystem_context seemingly not properly initialized!")


/**
 * Defines any state of a given session.
 */
struct session {
    struct list_head list;

    // TODO jitter suppression module?

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

static LIST_HEAD(session_list);
static session_subsystem_context* session_context;

void session_list_free();

session_subsystem_context* init_session_subsystem() {
    if (session_context != NULL) {
        return session_context;
    }

    session_context = calloc(1, sizeof(session_subsystem_context));
    // TODO do we need to do input sanitation (force the user to supply everything via parameters?
    //   => if we pass that via function args, we could declare some of the properties 'const'
    return session_context;
}

void close_session_subsystem() {
    session_list_free();

    free(session_context);
    session_context = NULL;
}


// TODO refactor, removing forward declaration
int session_transmit_next_encoded_frame(session_t* session);

session_t* session_find(enum SESSION_TYPE type, const u8* ether_source_host, const u8 *ether_destination_host) {
    struct session* session;

    list_for_each_entry(session, &session_list, list) {
        if (memcmp(session->session_id.source_address, ether_source_host, IEEE80211_ALEN) == 0
            && memcmp(session->session_id.destination_address, ether_destination_host, IEEE80211_ALEN) == 0
            && session->type == type) {
            // the additional type check above, allows us to have the SOURCE=DESTINATION
            // Not really supported by the ncm code itself (as we ignored packets from our own)
            // but helps with some flexibility in our unit tests.
            return session;
        }
    }

    return NULL;
}

// TODO rework the signature to not include the explicit definition of the session type
//  instead infer the session type from the mac addresses
//  enforce source!=destination; if self_addr=source => SOURCE; if self=destination => DESTINATION, otherwise INTERMEDIATE
//  needs adjustments in unit tests but should still work!
session_t* session_register(enum SESSION_TYPE session_type, const u8* ether_source_host, const u8 *ether_destination_host) {
    struct session* session;

    ASSERT_SESSION_CONTEXT();

    session = session_find(session_type, ether_source_host, ether_destination_host);
    if (session != NULL) {
        assert(session->type == session_type);
        return session;
    }


    session = calloc(1, sizeof(struct session));
    if (session == NULL) {
        DIE("Failed to calloc() session: %s", strerror(errno));
    }

    memcpy(session->session_id.source_address, ether_source_host, IEEE80211_ALEN);
    memcpy(session->session_id.destination_address, ether_destination_host, IEEE80211_ALEN);

    session->type = session_type;

    INIT_LIST_HEAD(&session->generations_list);

    for (int i = 0; i < session_context->generation_window_size; i++) {
        generation_init(
            &session->generations_list,
            session_type,
            session_context->moepgf_type,
            session_context->generation_size,
            MAX_PDU_SIZE,
            MEMORY_ALIGNMENT);
    }

    list_add(&session->list, &session_list);

    LOG_SESSION(LOG_INFO, session, "New session created");

    return session;
}

void session_free(session_t* session) {
    list_del(&session->list);

    // TODO potential jsm8022 module options cleanup

    generation_list_free(&session->generations_list);

    // TODO timeout delete

    // TODO potential logging file unlink (do we want/need to [re]implement that?)

    LOG_SESSION(LOG_INFO, session, "Session destroyed");

    free(session);
}

/**
 * Frees up the global session list.
 */
void session_list_free() {
    session_t *current, *tmp;

    list_for_each_entry_safe(current, tmp, &session_list, list) {
        session_free(current);
    }
}

// TODO add shortcut to call with moep_frame_t payload = moep_frame_get_payload(frame, &len); (u8* payload; // TODO static declaration?)
int session_encoder_add(session_t* session, u8* payload, size_t length) {
    NCM_GENERATION_STATUS status;

    assert(session->type == SOURCE && "Only a SOURCE session can add source frames!");

    status = generation_list_encoder_add(&session->generations_list, payload, length);
    if (status != GENERATION_STATUS_SUCCESS) {
        LOG_SESSION(LOG_WARNING, session, "Failed to store source frame(%d), discarding...", status);
        return -1;
    }

    session_transmit_next_encoded_frame(session);

    return 0;
}

// TODO add shortcut to call with moep_frame_t payload = moep_frame_get_payload(frame, &len); (u8* payload; // TODO static declaration?)
int session_decoder_add(session_t* session, u8* payload, size_t length, bool forward_os) { // TODO replace forward_os (experimental)
    static u8 buffer[MAX_PDU_SIZE] = {0}; // buffer to store data sent to the OS
    size_t data_length;
    NCM_GENERATION_STATUS  status;

    assert((session->type == DESTINATION || session->type == INTERMEDIATE) && "Only a non SOURCE session can add frames to decode!");
    ASSERT_SESSION_CONTEXT_PROPERTY(os_callback, NULL);

    status = generation_list_decoder_add_decoded(&session->generations_list, payload, length);

    if (status != GENERATION_STATUS_SUCCESS) {
        return -1;
    }

    if (!forward_os) {
        return 0;
    }

    // TODO sending back to OS is only valid for session type of DESTINATION.
    //   forwarders have to encode the frames, so forwarders are currently unsupported!
    for (;;) {
        data_length = 0;
        status = generation_list_next_decoded(&session->generations_list, sizeof(buffer), buffer, &data_length);

        if (status != GENERATION_STATUS_SUCCESS) {
            break;
        }

        session_context->os_callback(session, buffer, data_length);
    }

    // TODO reset future session destroy timeout
    return 0;
}


int session_transmit_next_encoded_frame(session_t* session) {
    static u8 buffer[MAX_PDU_SIZE] = {0};
    size_t length;
    NCM_GENERATION_STATUS status;

    ASSERT_SESSION_CONTEXT_PROPERTY(rtx_callback, NULL);

    // TODO the current implementation has a "encode" timer for **Every** generation,
    //  does this have any real reason? If not we can reduce "management overhead"
    //  by having **one** "encode" timer for every session, iterating over all generations
    //  checking what has to be sent out.

    status = generation_list_next_encoded_frame(&session->generations_list, sizeof(buffer), buffer, &length);

    if (status != GENERATION_STATUS_SUCCESS) {
        return -1;
    }

    session_context->rtx_callback(session, buffer, length);

    return 0;
}
