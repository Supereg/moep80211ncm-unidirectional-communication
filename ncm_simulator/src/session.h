//
// Created by Andreas Bauer on 22.02.21.
//

#ifndef MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_SESSION_H
#define MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_SESSION_H

#include <moep/system.h>
#include <moep/modules/moep80211.h>
#include <moepgf/moepgf.h>

struct session;
/// Opaque type for a `session` struct, representing all state of a session.
typedef struct session session_t;

/**
 * This struct serves as a global context object for the session subsystem.
 * It defines a bunch of parameters (e.g. needed for session initialization).
 * Additionally it is used to define callbacks (e.g. to handle encoded and decoded frames).
 *
 * See `init_session_subsystem` on how to properly initialize the session subsystem.
 */
typedef struct {
    int generation_size;
    int generation_window_size;
    enum MOEPGF_TYPE moepgf_type;

    // TODO int redundancy_schema; (validValues: 2, 0)

    // TODO params_jsm for the jitter suppression module?

    /**
     * Called when given encoded payload should be sent out over the radios.
     * @param session - The given session, this callback was executed for.
     * @param payload - The pointer to the payload to send out.
     * @param length - The length of the given payload.
     */
    int (*rtx_callback)(session_t* session, u8* payload, size_t length); // TODO we probably need to pass an moep_frame there in the future
    // TODO revise the return type (currently ignored?)
    /**
     * Called when a given frame was successfully decoded and should be handed over to the OS.
     * @param session - The given session, this callback was executed for.
     * @param payload - The pointer to the decoded payload.
     * @param length - The length of the given payload.
     */
    int (*os_callback)(session_t* session, u8* payload, size_t length); // TODO we probably need to pass an moep_frame there in the future
    // TODO revise the return type (currently ignored?)
} session_subsystem_context;

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

typedef struct {
    u8 source_address[IEEE80211_ALEN];
    u8 destination_address[IEEE80211_ALEN];
} session_id;

/* -------------------------------------------------------------------------------------------------------- */

/**
 * This function initializes the session subsystem.
 * It MUST be called before any of the session subsystem components can be used,
 * as required configuration is set withing the `session_subsystem_context`.
 *
 * The subsystem follows a singleton design, meaning one application can only initializes
 * exactly one session subsystem (with exactly one configuration).
 * I (Andreas Bauer <andi.bauer@tum.de>) think this is fair enough,
 * as it removes the need to always pass around the context struct.
 *
 * When called, the function creates and empty `session_subsystem_context` (storing it for future use)
 * and returns a pointer to said context.
 * The caller MUST immediately set all required configuration once the function returns.
 * TODO some words about mutability
 *
 * @return The newly created `session_subsystem_context` or the existing one if already called before.
 */
session_subsystem_context* init_session_subsystem();

/**
 * Shutdown the session subsystem. Closing all registered sessions and freeing the global `session_subsystem_context`.
 */
void close_session_subsystem();

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
 * @param session_type - The `SESSION_TYPE` of the created session (intermediate solution to manually specify it).
 * @param ether_source_host - Pointer to the mac address of the node packets are origination from. MUST be of length IEEE80211_ALEN.
 * @param ether_destination_host - Pointer to the mac address of the node packets are pointed towards. MUST be of length IEEE80211_ALEN.
 * @return A pointer to the existing session structure or to a newly created one, if it didn't exist yet.
 */
session_t* session_register(enum SESSION_TYPE session_type, const u8* ether_source_host, const u8 *ether_destination_host);

/**
 * Frees the memory of the given session.
 * @param session - The `session` to be freed.
 */
void session_free(session_t* session);

/* ---------------------------------------------------- */

/**
 * Adds a source frame (e.g. received from the OS) to the next available generation of the given session.
 * This might then lead to the `session_subsystem_context.rtx_callback` being called with the encoded frame.
 *
 * @param session - The `session_t` the frame should be added to.
 * @param payload - Pointer to the given payload.
 * @param length - The length of the payload.
 * @return Returns 0 for success, -1 for failure.
 */
int session_encoder_add(session_t* session, u8* payload, size_t length);

/**
 * Adds a encoded frame to the addressed generation of the given session.
 * Once the next frame can be successfully decoded, this might then lead to a call to
 * `session_subsystem_context.os_callback` with the fully decoded frame,
 * which can be handed back to the OS.
 *
 * @param session - The `session_t` for which the frame was received.
 * @param payload - Pointer to the received encoded payload.
 * @param length - The length of the payload.
 * @param forward_os - (Intermediate for simulation) Defines if the `os_callback` should be called immediately or skipped.
 * @return Returns 0 for success, -1 for failure.
 */
int session_decoder_add(session_t* session, u8* payload, size_t length, bool forward_os);

#endif //MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_SESSION_H
