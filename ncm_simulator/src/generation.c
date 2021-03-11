//
// Created by Andreas Bauer on 22.02.21.
//

#include "generation.h"

#include <assert.h>

#include <moepcommon/list.h>
#include <moepcommon/util.h>
#include <moeprlnc/rlnc.h>

#include "session.h"

/**
 * Struct holding all state information for a generation.
 */
struct generation {
    struct list_head list;
    /**
     * Sequence number uniquely identifying the given generation (in the context of a specific session).
     * The sequence number is forced into the range of uint16.
     * It starts at 0 and is monotonously increased for every "new" generation
     * (either by creating a new generation, or by freeing an old generation and allocating a new sequence number).
     *
     * TODO revise the maximum possible window size (we need to ensure no collisions are possible!)
     *   at least it must be hold: assert(sequence_number <= GENERATION_MAX_SEQUENCE_NUMBER - 1 && "");
     */
    int sequence_number;

    /**
     * The session type of the associated session (See `SESSION_TYPE`):
     */
    const enum SESSION_TYPE session_type;

    rlnc_block_t rlnc_block;

    /**
     * The maximum frame size possible to store in our coding matrix.
     */
    const size_t max_pdu_size;
    /**
     * Represents the size of our generation aka. the maximum dimension of our coding matrix
     * aka. the max amount of frames to be stored in this generation.
     */
    const int generation_size;

    /**
     * The next_pivot defines the next free pivot index of the coding matrix.
     * For receiving nodes (DESTINATION, INTERMEDIATE) this will define the next
     * pivot used to store the next coded packet.
     * For sending nodes (SOURCE) this will define the next pivot used to store the next source packet.
     */
    int next_pivot;

    /**
     * This counter reflects the remote dimension of our session,
     * at least for what we have received an acknowledgment for.
     */
    int remote_dimension;
};

generation_t* generation_find(struct list_head* generation_list, u16 sequence_number) {
    generation_t* generation;

    list_for_each_entry(generation, generation_list, list) {
        if (generation->sequence_number == sequence_number) {
            return generation;
        }
    }

    return NULL;
}

generation_t* generation_init(
    struct list_head* generation_list,
    enum SESSION_TYPE session_type,
    enum MOEPGF_TYPE moepgf_type,
    int generation_size,
    size_t max_pdu_size,
    size_t alignment) {
    struct generation* generation;

    struct generation* previous;
    int sequence_number = 0;

    // As of time of writing (March 2021) rlnc_block_encode() fails to do encoding
    // [the resulting buffer will not be written to, length is properly set] for generations with only one source frame and RLNC_STRUCTURED NOT set.
    // The issue seemingly doesn't occur with bigger GF types. Thus we currently disallow those GF types!
    assert(moepgf_type != MOEPGF2 && moepgf_type != MOEPGF4 && "Unable to init with MOEPGF2/MOEPGF4 as there are seemingly issues with libmoepgf");

    // generate next sequence number, required to start at zero and be continuous
    if (!list_empty(generation_list)) {
        previous = list_last_entry(generation_list, struct generation, list);
        sequence_number = previous->sequence_number + 1;
        // TODO ensure we don't init more generations than we have sequence numbers
    }

    generation = calloc(1, sizeof(struct generation));
    if (generation == NULL) {
        DIE("Failed to calloc() generation: %s", strerror(errno));
    }

    generation->rlnc_block = rlnc_block_init(generation_size, max_pdu_size, alignment, moepgf_type);
    if (generation->rlnc_block == NULL) {
        free(generation);
        DIE("Failed to rlnc_block_init(): %s", strerror(errno));
    }

    *((enum SESSION_TYPE*) &generation->session_type) = session_type;
    *((size_t*) &generation->max_pdu_size) = max_pdu_size;
    *((int*) &generation->generation_size) = generation_size;

    generation->sequence_number = sequence_number;

    generation->next_pivot = 0;
    generation->remote_dimension = 0;

    list_add_tail(&generation->list, generation_list);

    return generation;
}

void generation_free(generation_t* generation) {
    rlnc_block_free(generation->rlnc_block);
    free(generation);
}

void generation_list_free(struct list_head *generation_list) {
    struct generation *current, *tmp;

    list_for_each_entry_safe(current, tmp, generation_list, list) {
        list_del(&current->list);
        generation_free(current);
    }
}

void generation_reset(generation_t* generation, u16 new_sequence_number) {
    int ret;

    ret = rlnc_block_reset(generation->rlnc_block);
    if (ret != 0) {
        DIE("Failed to reset rlnc block, when trying to reset generation!");
    }

    generation->sequence_number = new_sequence_number;

    generation->next_pivot = 0;
    generation->remote_dimension = 0;
}


int generation_space_remaining(const generation_t* generation) {
    int size;
    size = generation->generation_size - generation->next_pivot;
    assert(size >= 0 && size <= generation->generation_size && "generation space is out of bounds");
    return size;
}

static bool generation_is_complete(const generation_t* generation) {
    switch (generation->session_type) {
        case SOURCE:
        case DESTINATION:
            return generation->remote_dimension >= generation->generation_size;
        case INTERMEDIATE:
            // TODO incorporate a ACK scheme in order to support forwarding nodes
            LOG(LOG_INFO, "Intermediate nodes are currently unsupported!");
            exit(-11);
    }

    DIE("Reached unsupported session type!");
}


/**
 * Traverses through the whole list of generations to clean out completed generations
 * (generations which were sent out and successfully received at the other end).
 * The generation list is ordered by generation state, generations which are currently worked on
 * are at the beginning (as we add new source frames iteratively), thus unused generations are at the end.
 * Once a generation (from the beginning of the list) is reset, the generation list is shifted accordingly,
 * such that the freed generations (after getting the next free sequence number set) are at the end of the list.
 *
 * @param generation_list - The list of `generation`s to traverse.
 * @return Returns the amount of generations which got reset as they were complete (and thus got moved to the beginning of the list).
 */
static int generation_list_advance(struct list_head* generation_list) {
    generation_t* next;
    generation_t* last;
    int next_sequence_number;
    int advance_count = 0;

    for (;;) {
        next = list_first_entry(generation_list, struct generation, list);
        last = list_last_entry(generation_list, struct generation, list);

        if (!generation_is_complete(next)) {
            break;
        }

        next_sequence_number = (last->sequence_number + 1) % (GENERATION_MAX_SEQUENCE_NUMBER + 1);
        // reset the given generation with initializing it with a new sequence number
        generation_reset(next, next_sequence_number);
        // moves the reset generation to the end of the list
        list_rotate_left(generation_list);

        advance_count++;
    }

    return advance_count;
}

static NCM_GENERATION_STATUS generation_encoder_add(generation_t* generation, u8* buffer, size_t length) {
    int ret;

    if (length > generation->max_pdu_size) {
        return GENERATION_PACKET_TOO_LARGE;
    }

    if (generation_space_remaining(generation) == 0) {
        return GENERATION_FULLY_TRAVERSED; // matrix is full, can't add any further source frames
    }

    ret = rlnc_block_add(generation->rlnc_block, generation->next_pivot, buffer, length);
    if (ret != 0) {
        LOG(LOG_ERR, "rlnc_block_decode() failed!");
        return GENERATION_GENERIC_ERROR;
    }

    generation->next_pivot++;

    // TODO current generation implementation has the concept of "locked" generations
    //   locked generation is basically a generation whose encoder is full.
    //   Do we need that? Seems to be less complicated as we don't have bidirectional streams right?

    return 0;
}

NCM_GENERATION_STATUS generation_list_encoder_add(struct list_head *generation_list, u8* buffer, size_t length) {
    generation_t* generation;
    NCM_GENERATION_STATUS status;

    list_for_each_entry(generation, generation_list, list) {
        if (generation_space_remaining(generation) == 0) {
            continue;
        }

        status = generation_encoder_add(generation, buffer, length);
        if (status != 0) {
            DIE("generation_list_encoder_add() failed to add buffer(%zu): %d", length, status);
        }

        return GENERATION_STATUS_SUCCESS;
    }

    return GENERATION_UNAVAILABLE;
}

static NCM_GENERATION_STATUS generation_next_encoded_frame(generation_t* generation, size_t max_length, u16* generation_sequence, u8* buffer, size_t* length_encoded) {
    int flags = 0;
    ssize_t length;

    if (generation->next_pivot == 0) {
        return GENERATION_EMPTY;
    }

    if (generation->session_type == SOURCE) {
        // if its the source node (aka not the forwarder) we want
        // to send out the frame in a structured way.
        flags |= RLNC_STRUCTURED;
    }

    length = rlnc_block_encode(generation->rlnc_block, buffer, max_length, flags);

    if (length < 0) {
        LOG(LOG_ERR, "generation_next_encoded_frame() failed, error message above!");
        return GENERATION_GENERIC_ERROR;
    }

    *generation_sequence = generation->sequence_number;
    *length_encoded = length;

    // TODO we currently assume acknowledgment of frames, once they are sent out.
    //   as we use RLNC_STRUCTURED and no forwarders currently, this works for now.
    generation->remote_dimension += 1;

    return GENERATION_STATUS_SUCCESS;
}

NCM_GENERATION_STATUS generation_list_next_encoded_frame(struct list_head* generation_list, size_t max_length, coded_packet_metadata_t* metadata, u8* buffer, size_t* length_encoded) {
    generation_t* generation;
    NCM_GENERATION_STATUS status;

    generation = list_first_entry(generation_list, generation_t, list);
    // TODO we would need to send out encoded frames for all not yet ACK generations(??? timer based?), not just the "next" one.
    status = generation_next_encoded_frame(generation, max_length, &metadata->generation_sequence, buffer, length_encoded);

    // generation_list_advance is to be called once we update any of the configuration state
    // (e.g. if we receive ACK/get a update remote dimension information),
    // as this may render a generation complete => thus we can reset it.
    // TODO this currently assumes instant ACKs, thus we will probably need to move this statement later!
    (void) generation_list_advance(generation_list);

    return status;
}

static NCM_GENERATION_STATUS generation_next_decoded(generation_t* generation, size_t max_length, u8* buffer, size_t* length_decoded) {
    ssize_t length;

    assert(generation->session_type != SOURCE && "Cannot decode from SOURCE session!");

    if (generation_space_remaining(generation) == 0) {
        return GENERATION_FULLY_TRAVERSED; // generation is already drained
    }

    length = rlnc_block_get(generation->rlnc_block, generation->next_pivot, buffer, max_length);
    if (length < 0) { // the destination buffer was probably too small!
        LOG(LOG_ERR, "generation_next_decoded() failed as rlnc_block_get() failed, see above!");
        return GENERATION_GENERIC_ERROR;
    }

    if (length == 0) { // no bytes read, the given pivot can't be decoded
        return GENERATION_NOT_YET_DECODABLE;
    }

    generation->next_pivot++;
    *length_decoded = length;

    return GENERATION_STATUS_SUCCESS;
}

NCM_GENERATION_STATUS generation_list_next_decoded(struct list_head* generation_list, size_t max_length, u8* buffer, size_t* length_decoded) {
    generation_t* generation;
    NCM_GENERATION_STATUS status;

    assert(!list_empty(generation_list) && "generation list cannot be empty");

    generation = list_first_entry(generation_list, struct generation, list);

    status = generation_next_decoded(generation, max_length, buffer, length_decoded);

    if (status == GENERATION_FULLY_TRAVERSED) { // generation is fully decoded
        int advanced_generations = generation_list_advance(generation_list);
        if (advanced_generations > 0) {
            // there are some new/free reset generations, just try again.
            return generation_list_next_decoded(generation_list, max_length, buffer, length_decoded);
        }
    }

    return status;
}

static NCM_GENERATION_STATUS generation_decoder_add_decoded(generation_t* generation, u8* buffer, size_t length) {
    int ret;

    if (length > generation->max_pdu_size) {
        return GENERATION_PACKET_TOO_LARGE;
    }

    /* No need for special checks, encoded packets can be added anytime:
     * - Either the packet is linear independent => this guarantees the coding matrix rank is not full
     * - or the packet is linear dependent => it is eliminated anyway
     */

    ret = rlnc_block_decode(generation->rlnc_block, buffer, length);
    if (ret != 0) {
        LOG(LOG_ERR, "rlnc_block_decode() failed!");
        return GENERATION_GENERIC_ERROR;
    }

    // we know for a fact, the remote dimension must equal to the rank of what we have received
    generation->remote_dimension = rlnc_block_rank_decode(generation->rlnc_block);

    return GENERATION_STATUS_SUCCESS;
}

NCM_GENERATION_STATUS generation_list_decoder_add_decoded(struct list_head* generation_list, coded_packet_metadata_t* metadata, u8* buffer, size_t length) {
    generation_t* generation;
    NCM_GENERATION_STATUS status;

    generation = generation_find(generation_list, metadata->generation_sequence);
    if (generation == NULL) {
        LOG(LOG_WARNING, "Received a seemingly late packet for the generation %d", metadata->generation_sequence);;
        return GENERATION_UNAVAILABLE;
    }

    status = generation_decoder_add_decoded(generation, buffer, length);

    return status;
}
