//
// Created by Andreas Bauer on 22.02.21.
//

#ifndef GENERATION_H
#define GENERATION_H

#include <moepcommon/list.h>
#include "session.h"

/**
 * Defines a value space for any errors which may be returned from the public interface of generation.c
 */
typedef enum NCM_GENERATION_STATUS_ENUM {
    /**
     * The given operation executed successfully.
     */
    GENERATION_STATUS_SUCCESS = 0,
    /**
     * A undescribed error occurred while executing the operation.
     */
    GENERATION_GENERIC_ERROR = -40701,
    /**
     * The given coding matrix of the given generation is fully traversed.
     * Either it is "full" in the sense that no more coded packets can be added or,
     * in the context of a `DESTINATION`, it is fully drained, meaning all packets were already decoded.
     */
    GENERATION_FULLY_TRAVERSED = -40702,
    /**
     * The given packet had unexpected size (probably exceeding the defined maximum pdu of the coding matrix).
     */
    GENERATION_PACKET_TOO_LARGE = -40703,
    /**
     * There wasn't enough (linear independent aka. "new") information in order to decode the next frame.
     */
    GENERATION_NOT_YET_DECODABLE = -40704,
    /**
     * The given generation is empty and doesn't hold any frames.
     */
    GENERATION_EMPTY = -40705,
    /**
     * Indicating that no suitable generation was available.
     */
    GENERATION_UNAVAILABLE = -40706,
} NCM_GENERATION_STATUS;

struct generation_packet_counter {
       int data;
       int ack;
       int redundant;
};

struct generation;
/// Opaque type for a `generation` struct
typedef struct generation generation_t;

/**
 * Defines all the possible generation event types.
 * The event system was created to fully decouple the generation.c code
 * from the session.c code e.g. making it easier to unit test.
 * It should be fairly simple to incorporate additional events in the future.
 */
enum GENERATION_EVENT {
    /**
     * Event triggered when the generation should be queued for a ACK transmission.
     * Event doesn't pass a `result` pointer.
     */
    GENERATION_EVENT_ACK,
    /**
     * Event triggered when the generation wants to send out a new coded packet.
     * Event doesn't pass a `result` pointer.
     */
    GENERATION_EVENT_ENCODED,
    /**
     * Event triggered before the generation is cleared and its generation sequence number is advanced.
     * Event doesn't pass a `result` pointer.
     */
    GENERATION_EVENT_RESET,
    /**
     * Event triggered when the generation wants to retrieve the current session redundancy,
     * calculated using the current link quality.
     * Event passes a `double` pointer to the `result` parameter to which the result must be written.
     */
    GENERATION_EVENT_SESSION_REDUNDANCY,
};

/**
 * `generation_event_handler` function pointer.
 * @param generation - The `generation_t` which triggered that event.
 * @param event - The event (see `enum GENERATION_EVENT`).
 * @param data - The `event_data` pointer passed to `generation_init`.
 * @param result - Some events expect a result to be returned. The result must be written into the `result` pointer.
 *      For events not expecting a result a NULL pointer is passed.
 */
typedef void (*generation_event_handler)(generation_t* generation, enum GENERATION_EVENT event, void* data, void* result);

/**
 * Initializes a new `generation_t` struct holding all state relevant to generation.
 *
 * @param generation_list - The `list_head` to the generation list, this generation should be inserted into.
 * @param session_type - The `SESSION_TYPE` of the session, the created generation will be added to.
 * @param moepgf_type - The `MOEPGF_TYPE` used for the coding matrix.
 * @param generation_size - The generation size (= amount of packets in one generation).
 * @param max_pdu_size - The maximum pdu size (= the maximum frame size).
 * @param alignment - Memory alignment of the coding matrix, passed to libmoeprlnc.
 * @param event_handler - Pointer to the `generation_event_handler`. Can be NULL to not register an event handler.
 * @param event_data - Pointer passed to the `data` argument of an `generation_event_handler` on every triggered event.
 * @return The created `generation_t`, guaranteed to be non NULL.
 */
generation_t* generation_init(
        struct list_head* generation_list,
        enum SESSION_TYPE session_type,
        enum MOEPGF_TYPE moepgf_type,
        int generation_size,
        size_t max_pdu_size,
        size_t alignment,
        generation_event_handler event_handler,
        void* event_data);

/**
 * Frees the memory for a given generation.
 * @param generation - The `generation` to be freed.
 */
void generation_free(generation_t* generation);

/**
 * Frees and empty's the given list of `generation`s.
 * @param generation_list - The `generation` list to empty and free.
 */
void generation_list_free(struct list_head *generation_list);

/**
 * Adds a source frame (e.g. received from the OS) to the next available generation in the provided generation list.
 *
 * @param generation_list - The `generation` list, to choose the next available generation from.
 * @param buffer - Pointer to the given payload.
 * @param length - The length of the payload.
 * @return Returns an `NCM_GENERATION_STATUS`.
 */
NCM_GENERATION_STATUS generation_list_encoder_add(struct list_head *generation_list, u8* buffer, size_t length);

/**
 * Creates the next encoded packet for the given generation.
 *
 * @param generation - The `generation` to generate a coded packet for.
 * @param max_length - Maximum PDU length.
 * @param generation_sequence - Pointer to which the `u16` generation sequence number is written to,
 *      if (and ONLY if) the function returns successfully.
 * @param buffer - Pointer to a buffer where the payload should be stored.
 * @param length_encoded - Pointer to store the length of the encoded payload.
 * @return Returns an `NCM_GENERATION_STATUS`.
 *  Note: parameters `generation_sequence` and `length_encoded` are only written to on a `GENERATION_STATUS_SUCCESS`.
 */
NCM_GENERATION_STATUS generation_next_encoded_frame(generation_t* generation, size_t max_length, u16* generation_sequence, u8* buffer, size_t* length_encoded);

/**
 * Used to retrieve the next decoded frame of the list of generations.
 *
 * @param generation_list - The list to iterate over the next available decodable frame.
 * @param max_length - The maximum size of the provided `buffer`.
 * @param buffer - Pointer to the buffer to write result into.
 * @param length_decoded - If a new decodable frame is available, its length is written to this pointer.
 *  Note: This pointer is only written to, if returned status equals to `GENERATION_STATUS_SUCCESS`
 * @return Returns a `NCM_GENERATION_STATUS`.
 */
NCM_GENERATION_STATUS generation_list_next_decoded(struct list_head* generation_list, size_t max_length, u8* buffer, size_t* length_decoded);

/**
 * Called to add a encoded frame received from the network.
 * @param generation_list - List of generations.
 * @param metadata - Pointer to a `coded_packet_metadata_t` struct, holding metadata relevant to the given coded packet.
 * @param buffer - Pointer to the buffer containing the encoded frame.
 * @param length - Length of the encoded frame.
 * @return Returns a `NCM_GENERATION_STATUS`.
 */
NCM_GENERATION_STATUS generation_list_receive_frame(struct list_head* generation_list, coded_packet_metadata_t* metadata, u8* buffer, size_t length);

void generation_write_ack_payload(struct list_head* generations_list, ack_payload_t* payload);

int generation_window_size(struct list_head* generations_list);

u16 generation_window_id(struct list_head* generations_list);

int generation_index(const generation_t* generation);

/**
 * Returns the statistics of the generation before it is being reset.
 * 
 * @param generation - the generation being reset/whose stats we want
 * @returns a struct generation_packet_counter holding the stats
 */
struct generation_packet_counter* generation_get_counters(generation_t* generation);

/**
 * @param generation - The `generation_t` to check.
 * @return Returns true if the given generation holds no information.
 */
bool generation_empty(const generation_t* generation);

/**
 * Returns the amount of free space inside the coding matrix for the given `generation_t`.
 *
 * Equivalent formulations:
 *  - The amount of source frames yet to be sent.
 *  - The amount of encoded frames yet to received (to later be decoded/recoded).
 *
 * @param generation - The `generation_t` to return the remaining space for.
 * @return Returns the amount of free space inside the coding matrix.
 */
int generation_space_remaining(const generation_t* generation);

int generation_list_space_remaining(struct list_head* generation_list);

bool generation_is_complete(const generation_t* generation);

bool generation_remote_decoded(const generation_t* generation);

bool generation_list_remote_decoded(struct list_head* generation_list);

int generation_list_space_remaining(struct list_head* generations_list);

#endif //GENERATION_H
