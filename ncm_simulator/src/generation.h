//
// Created by Andreas Bauer on 22.02.21.
//

#ifndef MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_GENERATION_H
#define MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_GENERATION_H

#include <moepcommon/list.h>
#include "session.h"

#define GENERATION_MAX_SEQUENCE_NUMBER INT16_MAX

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

/**
 * Initializes a new `generation_t` struct holding all state relevant to generation.
 *
 * @param generation_list - The `list_head` to the generation list, this generation should be inserted into.
 * @param session_type - The `SESSION_TYPE` of the session, the created generation will be added to.
 * @param moepgf_type - The `MOEPGF_TYPE` used for the coding matrix.
 * @param generation_size - The generation size (= amount of packets in one generation).
 * @param max_pdu_size - The maximum pdu size (= the maximum frame size).
 * @param alignment - Memory alignment of the coding matrix, passed to libmoeprlnc.
 * @return The created `generation_t`, guaranteed to be non NULL.
 */
generation_t* generation_init(
        struct list_head* generation_list,
        enum SESSION_TYPE session_type,
        enum MOEPGF_TYPE moepgf_type,
        int generation_size,
        size_t max_pdu_size,
        size_t alignment);

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

/**
 * Adds a source frame (e.g. received from the OS) to the next available generation in the provided generation list.
 * This might then lead to the `session_subsystem_context.rtx_callback` being called with the encoded frame.
 *
 * @param generation_list - The `generation` list, to choose the next available generation from.
 * @param buffer - Pointer to the given payload.
 * @param length - The length of the payload.
 * @return Returns an `NCM_GENERATION_STATUS`.
 */
NCM_GENERATION_STATUS generation_list_encoder_add(struct list_head *generation_list, u8* buffer, size_t length);

// TODO docs
NCM_GENERATION_STATUS generation_list_next_encoded_frame(struct list_head* generation_list, size_t max_length, u8* buffer, size_t* length_encoded);

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
 * @param buffer - Pointer to the buffer containing the encoded frame.
 * @param length - Length of the encoded frame.
 * @return Returns a `NCM_GENERATION_STATUS`.
 */
NCM_GENERATION_STATUS generation_list_decoder_add_decoded(struct list_head* generation_list, u8* buffer, size_t length);

#endif //MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_GENERATION_H
