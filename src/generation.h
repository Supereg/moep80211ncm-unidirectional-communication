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

struct generation;
/// Opaque type for a `generation` struct
typedef struct generation generation_t;

enum GENERATION_EVENT {
    GENERATION_EVENT_ACK,
    GENERATION_EVENT_ENCODED,
    GENERATION_EVENT_RESET,
    GENERATION_EVENT_SESSION_REDUNDANCY,
};

// TODO document the result part (might be NULL)
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
 * // TODO document the two new parameters?
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
 * This might then lead to the `session_subsystem_context_t.rtx_callback` being called with the encoded frame.
 *
 * @param generation_list - The `generation` list, to choose the next available generation from.
 * @param buffer - Pointer to the given payload.
 * @param length - The length of the payload.
 * @return Returns an `NCM_GENERATION_STATUS`.
 */
NCM_GENERATION_STATUS generation_list_encoder_add(struct list_head *generation_list, u8* buffer, size_t length);

/**
 * Creates the next encoded packet for the given generation list.
 * @param generation_list - The list of generations to choose a generation from.
 * @param max_length - Maximum PDU length.
 * @param metadata - Pointer to a `coded_packet_metadata_t` to **collect** and store the given metadata.
 * @param buffer - Pointer to a buffer where the payload should be stored.
 * @param length_encoded - Pointer to store the length of the encoded payload.
 * @return Returns an `NCM_GENERATION_STATUS`. Note parameters `metadata` and `length_encoded` are only written to on a `GENERATION_STATUS_SUCCESS`.
 */
// TODO NCM_GENERATION_STATUS generation_list_next_encoded_frame(struct list_head* generation_list, size_t max_length, coded_packet_metadata_t* metadata, u8* buffer, size_t* length_encoded);
NCM_GENERATION_STATUS generation_next_encoded_frame(generation_t* generation, size_t max_length, u16* generation_sequence, u8* buffer, size_t* length_encoded);

/**
 * Used to retrieve the next decodable frame of the list of generations.
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

int generation_index(struct list_head* generations_list, generation_t* generation);

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

bool generation_is_complete(const generation_t* generation);

bool generation_remote_decoded(const generation_t* generation);

bool generation_list_remote_decoded(struct list_head* generation_list);

#endif //GENERATION_H
