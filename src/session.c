//
// Created by Andreas Bauer on 22.02.21.
//

#include "global.h"
#include "session.h"

#include <assert.h>
#include <time.h>

#include <moepcommon/list.h>
#include <moepcommon/util.h>
#include <moepcommon/timeout.h>

#include "generation.h"

#include "neighbor.h"
#include "qdelay.h"

void session_free(session_t* session); // forward declaration used in session_callback_destroy()
void session_list_free(session_subsystem_context_t* context); // forward declaration used in session_subsystem_close()
static void session_activity(session_t* session); // forward declaration used in generation_init()

static void session_generation_event_handler(generation_t* generation, enum GENERATION_EVENT event, void* data, void* result);
static int session_destroy_callback(timeout_t timeout, u32 overrun, void* data);
static int session_ack_callback(timeout_t timeout, u32 overrun, void* data);

struct session_timeouts {
    /**
     * Timeout ran with `SESSION_TIMEOUT` delay, removing/cleaning up the session
     * when timeout is reached. Timeout is reset for every activity on the session.
     */
    timeout_t destroy;
    /**
     * Acknowledgment timer used to debounce sending out ACKs for our generations.
     * On every received coded packet, the timer will be scheduled with `SESSION_ACK_TIMEOUT` milliseconds,
     * combining ACKs if multiple packets receive consecutively.
     */
    timeout_t ack;
};

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

    struct session_timeouts timeouts;

    /**
     * Linked list, containing all `generation_t`s associated with the given session.
     */
    struct list_head generations_list;

    /**
     * packet counters for statistics
     */
    struct session_packet_counter ctr;
};


session_subsystem_context_t* session_subsystem_init(
    int generation_size,
    int generation_window_size,
    enum MOEPGF_TYPE moepgf_type,
    u8* hw_address,
    encoded_payload_callback rtx_callback,
    decoded_payload_callback os_callback,
    int redundancy_scheme) {
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

    context->redundancy_scheme = redundancy_scheme;

    INIT_LIST_HEAD(&context->sessions_list);

    return context;
}

void session_subsystem_close(session_subsystem_context_t* context) {
    session_list_free(context);

    free(context);
}


// generates the filename for statistics saving
static char *session_get_log_fn(session_t* s)
{
    static char filename[1000];
    u8* session_id;

    session_id = (u8 *) &s->session_id;
    snprintf(filename, 1000, "%s%d_%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x.log",
        SESSION_LOG_FILE_PREFIX,
        getpid(),
        session_id[ 0], session_id[ 1], session_id[ 2], session_id[ 3],
        session_id[ 4], session_id[ 5], session_id[ 6], session_id[ 7],
        session_id[ 8], session_id[ 9], session_id[10], session_id[11]);
    return filename;
}

void session_log_state(session_subsystem_context_t* context) {
    session_t* pos;
    char *filename;
    FILE *file;
    u8* session_id;
    int i;

    list_for_each_entry(pos, &context->sessions_list, list) {
        session_id = (u8 *) &pos->session_id;
        filename = session_get_log_fn(pos);
        file = fopen(filename, "a");
        if (!file)
			DIE("cannot open file: %s", filename);
        fprintf(file, "%lu,", (unsigned long) time(NULL));
        for (i = 0; i < 12; i++) {
            fprintf(file, "%02x", session_id[i]);
        }
        fprintf(file, ",%d,", pos->ctr.data);
        fprintf(file, "%d,", pos->ctr.ack);
        fprintf(file, "%d\n", pos->ctr.redundant);
        fclose(file);
    }
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
    int ret;

    session_type = session_type_derived(context, ether_source_host, ether_destination_host);
    session = session_find(context, ether_source_host, ether_destination_host);

    if (session != NULL) {
        assert(session->type == session_type);
        return session;
    }

    session = calloc(1, sizeof(struct session));
    if (session == NULL) {
        DIE_SESSION(session, "Failed to calloc() session: %s", strerror(errno));
    }

    session->context = context;

    memcpy(session->session_id.source_address, ether_source_host, IEEE80211_ALEN);
    memcpy(session->session_id.destination_address, ether_destination_host, IEEE80211_ALEN);

    session->type = session_type;
    INIT_LIST_HEAD(&session->generations_list);

    ret = timeout_create(CLOCK_MONOTONIC, &session->timeouts.destroy, session_destroy_callback, session);
    if (ret != 0) {
        session_free(session);
        DIE("session_register() failed to create destroy timeout: %s", strerror(errno));
    }

    if (session_type == DESTINATION || session_type == INTERMEDIATE) {
        ret = timeout_create(CLOCK_MONOTONIC, &session->timeouts.ack, session_ack_callback, session);
        if (ret != 0) {
            session_free(session);
            DIE("session_register() failed to create ack timeout: %s", strerror(errno));
        }
    }

    for (int i = 0; i < context->generation_window_size; i++) {
        (void) generation_init(
            &session->generations_list,
            session_type,
            context->moepgf_type,
            context->generation_size,
            GENERATION_MAX_PDU_SIZE,
            MEMORY_ALIGNMENT,
            session_generation_event_handler,
            session);
    }

    list_add(&session->list, &context->sessions_list);

    session_activity(session); // initializes the destroy_timeout!

    LOG_SESSION(LOG_INFO, session, "New session created");

    return session;
}

session_id* session_get_id(session_t* session) {
    return &session->session_id;
}

enum SESSION_TYPE session_get_type(session_t* session) {
    return session->type;
}

static int session_space_remaining(session_t* session) {
    return generation_list_space_remaining(&session->generations_list);
}

int session_context_min_space_remaining(session_subsystem_context_t* context) {
    session_t* s;
	int ret = GENERATION_SIZE;

	list_for_each_entry(s, &context->sessions_list, list)
		ret = min(session_space_remaining(s), ret);

	return ret;
}

void session_free(session_t* session) {
    int ret;

    list_del(&session->list);

    generation_list_free(&session->generations_list);

    if (session->timeouts.destroy != NULL) {
        ret = timeout_delete(session->timeouts.destroy);
        if (ret != 0) {
            DIE("Failed session_free() to timeout_delete(): %s", strerror(errno));
        }
    }

    if (session->timeouts.ack != NULL) {
        ret = timeout_delete(session->timeouts.ack);
        if (ret != 0) {
            DIE("Failed session_free() to timeout_delete(): %s", strerror(errno));
        }
    }

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

static void session_activity(session_t* session) {
    int ret;

    assert(session->timeouts.destroy != NULL && "session destroy timeout was never initialized!");

    ret = timeout_settime(session->timeouts.destroy, 0, timeout_msec(SESSION_TIMEOUT, 0));
    if (ret != 0) {
        DIE_SESSION(session, "session_activity() failed to timeout_settime() for destroy timeout: %s", strerror(errno));
    }
}

static void session_timeout_ack_schedule(session_t* session) {
    int ret;
    ret = timeout_settime(session->timeouts.ack, TIMEOUT_FLAG_INACTIVE, timeout_msec(SESSION_ACK_TIMEOUT, 0));

    if (ret != 0) {
        DIE_SESSION(session, "session_timeout_ack_schedule() failed timeout_settime(): %s", strerror(errno));
    }
}

static void session_timeout_ack_reset(session_t* session) {
    int ret;
    ret = timeout_clear(session->timeouts.ack);

    if (ret != 0) {
        DIE_SESSION(session, "session_timeout_ack_reset() failed timeout_clear(): %s", strerror(errno));
    }
}


int session_encoder_add(session_t* session, u16 ether_type, u8* payload, size_t payload_length) {
    NCM_GENERATION_STATUS status;
    static u8 buffer[GENERATION_MAX_PDU_SIZE] = {0};
    size_t buffer_length;
    // see docs of `coded_payload_metadata`
    coded_payload_metadata_t* metadata;

    assert(session->type == SOURCE && "Only a SOURCE session can add source frames!");

    session_activity(session);

    // 1. prepend our frame buffer with the `coded_payload_metadata` metadata
    //   to preserve ether type and length information in our linear combinations of packets

    buffer_length = payload_length + sizeof(coded_payload_metadata_t);
    // TODO we later need to transport the coding vectors + the buffer in a single PDU,
    //   thus this check would somehow need to account for that
    //   (the check will be repeated later [with also checking coding coefficients], but is probably better to catch that early?
    if (buffer_length > GENERATION_MAX_PDU_SIZE) {
        LOG_SESSION(LOG_WARNING, session, "Received a source frame which is bigger than the maximum of %lu bytes",
                    (GENERATION_MAX_PDU_SIZE - sizeof(coded_payload_metadata_t)));
        return -1;
    }

    metadata = (void*) buffer;
    metadata->payload_type = htole16(be16toh(ether_type)); // iee 80211 is LE

    memcpy(buffer + sizeof(coded_payload_metadata_t), payload, payload_length);


    // 2. add the buffer (with prepended `coded_payload_metadata`) to the next available generation in our list.
    status = generation_list_encoder_add(&session->generations_list, buffer, buffer_length);
    if (status != GENERATION_STATUS_SUCCESS) {
        // most probably happens when our generations are full and we can't store any further frames.
        LOG_SESSION(LOG_WARNING, session, "Failed to store source frame(%d), discarding...", status);
        return -1;
    }

    return 0;
}

static void session_check_for_decoded_frames(session_t* session) {
    NCM_GENERATION_STATUS  status;
    static u8 buffer[GENERATION_MAX_PDU_SIZE] = {0};
    size_t buffer_length;

    coded_payload_metadata_t* metadata;
    u8* payload;
    size_t payload_length;

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
        payload = buffer + sizeof(coded_payload_metadata_t);
        payload_length = buffer_length - sizeof(coded_payload_metadata_t);

        // ieee 80211 is LE, while ieee 8023 is BE
        u16 ether_type = htobe16(le16toh(metadata->payload_type));

        session->context->os_callback(session->context, session, ether_type, payload, payload_length);
    }
}

int session_decoder_add(session_t* session, coded_packet_metadata_t* metadata, u8* payload, size_t length) {
    NCM_GENERATION_STATUS status;

    if (session->context->moepgf_type != metadata->gf) {
        LOG_SESSION(LOG_ERR, session, "Received frame with dissimilar gf type. remote=%d; local=%d. Discarding...",
                    session->context->moepgf_type, metadata->gf);
        return -1;
    }

    if (session->context->generation_window_size != metadata->window_size) {
        LOG_SESSION(LOG_ERR, session, "Received frame with dissimilar window sizes. remote=%d; local=%d. Discarding...",
                    session->context->generation_window_size, metadata->window_size);
        return -1;
    }

    assert((metadata->ack && (session->type == SOURCE || session->type == INTERMEDIATE))
        || (!metadata->ack && (session->type == DESTINATION || session->type == INTERMEDIATE)));

    session_activity(session);

    status = generation_list_receive_frame(&session->generations_list, metadata, payload, length);
    if (status != GENERATION_STATUS_SUCCESS) {
        if (status == GENERATION_UNAVAILABLE && !metadata->ack) {
            // stale coded packet, which is fine, we will retransmit a ACK
            return 0;
        }
        // we require in generation_list_receive_frame that any non-zero status logs an error
        // no need to do a generic "something went wrong" message here
        return -1;
    }

    if (session->type == DESTINATION) {
        session_check_for_decoded_frames(session);
    }

    return 0;
}

/**
 * generates the metadata values for a given session
 * @param metadata pointer to metadata struct that is to be filled out
 * @param session pointer to current session
 * @param ack flag if acknowledgment flag is to be set
 */
static void session_packet_metadata(coded_packet_metadata_t* metadata, session_t* session, bool ack) {
    metadata->sid = *(session_get_id(session));
    metadata->generation_sequence = 0; // this will be set by generation_next_encoded_frame() afterwards
    metadata->window_id = generation_window_id(&session->generations_list);
    metadata->gf = session->context->moepgf_type;
    metadata->ack = ack;
    metadata->window_size = session->context->generation_window_size;
}

int session_transmit_encoded_frame(session_t* session, generation_t* generation) {
    NCM_GENERATION_STATUS status;
    static u8 buffer[GENERATION_MAX_PDU_SIZE] = {0};
    static coded_packet_metadata_t metadata;
    size_t length;

    session_packet_metadata(&metadata, session, 0);

    status = generation_next_encoded_frame(generation, sizeof(buffer), &metadata.generation_sequence, buffer, &length);

    if (status != GENERATION_STATUS_SUCCESS) {
        return -1;
    }

    session->context->rtx_callback(session->context, session, &metadata, buffer, length);

    return 0;
}

int session_transmit_ack_frame(session_t* session) {
    static coded_packet_metadata_t metadata;
    ack_payload_t* payload;

    payload = calloc(1, sizeof(ack_payload_t) * session->context->generation_window_size);
    if (payload == NULL) {
        DIE_SESSION(session, "Failed session_transmit_ack_frame() to calloc() ack_payload_t");
    }

    generation_write_ack_payload(&session->generations_list, payload);

    session_packet_metadata(&metadata, session, true);

    session->context->rtx_callback(session->context, session, &metadata, (u8 *) payload,
                                   (sizeof(ack_payload_t) * session->context->generation_window_size));

    free(payload);

    return 0;
}

void session_commit(session_t* session, generation_t* generation) {
    struct generation_packet_counter* ctr;

    ctr = generation_get_counters(generation);
    session->ctr.data += ctr->data;
    session->ctr.ack += ctr->ack;
    session->ctr.redundant += ctr->redundant;
}

/**
 * Calculates the number of transmission we expect to be required to successfully transmit a single frame,
 * based on the current link quality.
 * The returned value is in the interval of [1.0, infinity).
 */
static double session_redundancy(session_t* session) {
   double redundancy;
   u8* remote_address;

   assert(session->type == SOURCE || session->type == INTERMEDIATE);
   remote_address = session->session_id.destination_address;

    switch (session->context->redundancy_scheme) {
        case 0:
            redundancy = 1.0 / nb_ul_quality(remote_address, NULL, NULL);
            break;
        case 1:
            redundancy = nb_ul_redundancy(remote_address);
            break;
        default:
            DIE_SESSION(session, "Unsupported redundancy scheme: %d", session->context->redundancy_scheme);
    }

   return redundancy;
}

static void session_generation_event_handler(generation_t* generation, enum GENERATION_EVENT event, void* data, void* result) {
    session_t* session;
    session = data;

    switch (event) {
        case GENERATION_EVENT_ACK:
            // be aware, that the generation pointer might be some "random" generation
            // e.g. for ACK retransmission of generations, where generation was already freed
            session_timeout_ack_schedule(session);
            break;
        case GENERATION_EVENT_ENCODED:
            session_transmit_encoded_frame(session, generation);
            break;
        case GENERATION_EVENT_RESET:
            session_commit(session, generation);
            break;
        case GENERATION_EVENT_SESSION_REDUNDANCY:
            *(double*) result = session_redundancy(session);
            break;
        default:
            DIE_SESSION(session, "Received unknown generation event: %d", event);
    }
}

static int session_destroy_callback(timeout_t timeout, u32 overrun, void* data) {
    (void) timeout;
    (void) overrun;
    session_t* session = data;
    session_free(session);
    return 0;
}

static int session_ack_callback(timeout_t timeout, u32 overrun, void* data) {
    (void) timeout;
    (void) overrun;
    session_t* session;
    assert(data != NULL && "session pointer not present on session_ack_callback()");

    session = data;

    if (overrun) {
        LOG_SESSION(LOG_WARNING, session, "session_ack_callback() detected %d skipped executions (overruns)", overrun);
    }

    // Some sort of debounce mechanism for acknowledgments
    // though not sure where this check comes from.
    // It was copied from the bidirectional session management as is.
    // TODO magic constant. Where does it come from?
    if (qdelay_packet_cnt() > 10) {
        timeout_settime(session->timeouts.ack, TIMEOUT_FLAG_SHORTEN,
                        timeout_usec( (s64) ((double) SESSION_ACK_TIMEOUT * 0.5 * 1000), 0));
        return 0;
    }


    session_transmit_ack_frame(session);
    session_timeout_ack_reset(session);

    return 0;
}
