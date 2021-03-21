//
// Created by Andreas Bauer on 22.02.21.
//

#ifndef MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_SESSION_H
#define MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_SESSION_H

#include "global.h"

#include <moepcommon/list.h>
#include <moep/system.h>
#include <moep/modules/moep80211.h>
#include <moepgf/moepgf.h>

/**
 * Timeout in milliseconds a session has to be idle before it gets destroyed.
 */
#define SESSION_TIMEOUT 30000
#define SESSION_ACK_TIMEOUT 1

struct session;
/**
 * Opaque type for a `session` struct, representing all state of a session.
 * Seemingly inconsistent with the rest of the project, we don't use pointer typedefs:
 * https://stackoverflow.com/questions/3781932/is-typedefing-a-pointer-type-considered-bad-practice
 */
typedef struct session session_t;

struct session_subsystem_context;

typedef struct {
    u8 source_address[IEEE80211_ALEN];
    u8 destination_address[IEEE80211_ALEN];
} session_id;

/**
 * This struct is used to store any relevant metadata with the coded **payload**.
 * As we send out random linear combinations of our source frames,
 * there is no straightforward way to send additional information associated with those frames.
 * Thus we just prepend our encoded buffer with below `coded_payload_metadata` struct,
 * appended with the original payload.
 */
typedef struct coded_payload_metadata {
    /**
     * Equivalent to the ethertype, specifying the L3 protocol.
     * Stored in LE format.
     */
    u16 payload_type;
} coded_payload_metadata_t;

/**
 * This struct is used to store any metadata with the coded **packet**.
 * This includes e.g. addressing/identification of the given session and generation.
 * This is basically a internal structure to pass around information
 * store in the 'coded' extension header of a moep 80211 packet.
 */
typedef struct coded_packet_metadata {
    // The Session ID
    session_id sid;
    // The sequence number of the generation a given encoded packet stems from or is addressed to.
    // For ack frames this value is zero and has no meaning
    u16 generation_sequence;
    // The smallest sequence number of the current sequence number window
    u16 window_id;
    // Galois field type
    enum MOEPGF_TYPE gf;
    // Acknowledgment flag
    bool ack;
    // generation windows size
    u8 window_size;
} coded_packet_metadata_t;

// This struct represents the payload that is transported via an ack
typedef struct ack_payload {
    u16 sequence_number;
    u8 receiver_dim;
} ack_payload_t;

/**
 * Generic callback type for handling encoded payloads.
 * Note: memory of provided parameters MUST NOT be accessed after the given function returned!
 *
 * @param context - The `session_subsystem_context`.
 * @param session - The given session, this callback was executed for.
 * @param metadata - Pointer to a `coded_packet_metadata_t` struct, holding metadata relevant to the given coded packet.
 * @param payload - The pointer to the payload.
 * @param length - The length of the payload.
 * @returns 0 success, -1 error
 */
typedef int (*encoded_payload_callback)(struct session_subsystem_context* context, session_t* session, coded_packet_metadata_t* metadata, u8* payload, size_t length);

/**
 * Generic callback type for handling decoded payloads.
 * Note: memory of provided parameters MUST NOT be accessed after the given function returned!
 *
 * @param context - The `session_subsystem_context`.
 * @param session - The given session, this callback was executed for.
 * @param ether_type - The ether type in network byte order.
 * @param payload - The pointer to the payload.
 * @param length - The length of the payload.
 * @returns 0 success, -1 error
 */
typedef int (*decoded_payload_callback)(struct session_subsystem_context* context, session_t* session, u16 ether_type, u8* payload, size_t length);

/**
 * This struct serves as a global context object for the session subsystem.
 * It defines a bunch of parameters (e.g. needed for session initialization).
 * Additionally it is used to define callbacks (e.g. to handle encoded and decoded frames).
 *
 * See `session_subsystem_init` on how to properly initialize the session subsystem.
 */
typedef struct session_subsystem_context {
    const int generation_size;
    const int generation_window_size;
    const enum MOEPGF_TYPE moepgf_type;

    // TODO int redundancy_schema; (validValues: 2, 0)

    u8 local_address[IEEE80211_ALEN];

    /**
     * Called when given encoded payload should be sent out over the radios.
     */
    encoded_payload_callback rtx_callback;
    /**
     * Called when a given frame was successfully decoded and should be handed over to the OS.
     */
    decoded_payload_callback os_callback;

    /**
     * Linked list to store all registered sessions.
     */
    struct list_head sessions_list;
} session_subsystem_context_t;

/**
 * Defines the type of `session`
 */
enum SESSION_TYPE {
    /**
     * The local host generates packets for the given session.
     */
    SOURCE = 0,
    /**
     * The local host consumes packets of the given session.
     */
    DESTINATION = 1,
    /**
     * The local host acts as an intermediate (aka. forwarder) node for the given session.
     */
    INTERMEDIATE = 2,
};


#define LOG_SESSION(loglevel, session, message, ...) \
do { \
    u8* source_address = session_get_id(session)->source_address; \
    u8* destination_address = session_get_id(session)->destination_address; \
    enum SESSION_TYPE type = session_get_type(session); \
    LOG(loglevel, message" (type: %d, source: %02x:%02x:%02x:%02x:%02x:%02x, destination: %02x:%02x:%02x:%02x:%02x:%02x)", \
        ## __VA_ARGS__ , \
        type, \
        source_address[0], source_address[1], source_address[2], \
        source_address[3], source_address[4], source_address[5], \
        destination_address[0], destination_address[1], destination_address[2], \
        destination_address[3], destination_address[4], destination_address[5]); \
} while (0)

#define DIE_SESSION(session, message, ...) \
do { \
    u8* source_address = session_get_id(session)->source_address; \
    u8* destination_address = session_get_id(session)->destination_address; \
    DIE(message" (source: %02x:%02x:%02x:%02x:%02x:%02x, destination: %02x:%02x:%02x:%02x:%02x:%02x)", \
        ## __VA_ARGS__ , \
        source_address[0], source_address[1], source_address[2], \
        source_address[3], source_address[4], source_address[5], \
        destination_address[0], destination_address[1], destination_address[2], \
        destination_address[3], destination_address[4], destination_address[5]); \
} while (0)

/* -------------------------------------------------------------------------------------------------------- */

/**
 * This function initializes a new session subsystem context.
 * It is used to store any relevant configurations and context used for the session subsystem.
 * The context also stores the list of all registered session,
 * and is thus required for the `session_register` call.
 *
 * For a detailed documentation of the required parameters,
 * have a look at the documentation of the `struct session_subsystem_context`.
 *
 * @return Returns a new `session_subsystem_context_t`, initialized with the provided parameters.
 */
session_subsystem_context_t* session_subsystem_init(
    int generation_size,
    int generation_window_size,
    enum MOEPGF_TYPE moepgf_type,
    u8* hw_address,
    encoded_payload_callback rtx_callback,
    decoded_payload_callback os_callback);

/**
 * Shutdown the session subsystem. Closing all registered sessions and freeing the global `session_subsystem_context_t`.
 * @param context - The `session_subsystem_context_t` context to be freed/closed.
 */
void session_subsystem_close(session_subsystem_context_t* context);

/* -------------------------------------------------------------------------------------------------------- */

/**
 * Finds or creates a new `session` for the given flow, defined by the pair of mac addresses (source and destination).
 *
 * Example:
 * A node S with a bidirectional session to and from node T would have two session:
 * - outgoing with SOURCE=S, DESTINATION=T
 * - ingoing with SOURCE=T, DESTINATION=S
 * Any intermediate/forwarding node in between, will also have the same two sessions.
 * Thus the tuple of those two mac addresses act as the unique identifier for a session (`session_id`)
 *
 * @param context - The `session_subsystem_context_t`, to be created using `session_subsystem_init`.
 * @param ether_source_host - Pointer to the mac address of the node packets are origination from. MUST be of length IEEE80211_ALEN.
 * @param ether_destination_host - Pointer to the mac address of the node packets are pointed towards. MUST be of length IEEE80211_ALEN.
 * @return A pointer to the existing session structure or to a newly created one, if it didn't exist yet.
 */
session_t* session_register(session_subsystem_context_t* context, const u8* ether_source_host, const u8 *ether_destination_host);

/**
 * Returns the pointer to the `session_id` of a given `session_t`.
 * @param session - The given `session_t`
 * @return The `session_id` of the `session_t`
 */
session_id* session_get_id(session_t* session);

/**
 * Returns the `SESSION_TYPE` of a given `session_t`.
 */
enum SESSION_TYPE session_get_type(session_t* session);

/* ---------------------------------------------------- */

/**
 * Adds a source frame (e.g. received from the OS) to the next available generation of the given session.
 * This might then lead to the `session_subsystem_context_t.rtx_callback` being called with the encoded frame.
 *
 * @param session - The `session_t` the frame should be added to.
 * @param ether_type - The ethertype in network byte order
 * @param payload - Pointer to the given payload.
 * @param payload_length - The payload_length of the payload.
 * @return Returns 0 for success, -1 for failure.
 */
int session_encoder_add(session_t* session, u16 ether_type, u8* payload, size_t payload_length);

/**
 * Adds a encoded frame to the addressed generation of the given session.
 * Once the next frame can be successfully decoded, this might then lead to a call to
 * `session_subsystem_context_t.os_callback` with the fully decoded frame,
 * which can be handed back to the OS.
 *
 * @param session - The `session_t` for which the frame was received.
 * @param metadata - Pointer to a `coded_packet_metadata_t` struct, holding metadata relevant to the given coded packet.
 * @param payload - Pointer to the received encoded payload.
 * @param length - The length of the payload.
 * @return Returns 0 for success, -1 for failure.
 */
int session_decoder_add(session_t* session, coded_packet_metadata_t* metadata, u8* payload, size_t length);

#endif //MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_SESSION_H
