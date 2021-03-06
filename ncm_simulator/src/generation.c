//
// Created by Andreas Bauer on 22.02.21.
//

#include <assert.h>

#include <moepcommon/list.h>
#include <moepcommon/util.h>

#include <moeprlnc/rlnc.h>

#include "session.h"
#include "generation.h"

// TODO document
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
    enum SESSION_TYPE session_type;

    // TODO do we need a similar thing to the state struct?

    rlnc_block_t rlnc_block;

    /**
     * The maximum frame size possible to store in our coding matrix.
     */
    size_t max_pdu_size;

    /**
     * The next_pivot defines the next free pivot index of the coding matrix.
     * For receiving nodes (DESTINATION, INTERMEDIATE) this will define the next
     * pivot used to store the next coded packet.
     * For sending nodes (SOURCE) this will define the next pivot used to store the next source packet.
     */
    int next_pivot;
    int coding_matrix_dimension;

    // TODO ACK timeout?
};

// TODO instead of passing everything as an a distinct argument we could just pass
//  the whole `session_subsystem_context`, containing pretty much all values [could create unwanted coupling though?]
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

    // generate next sequence number, required to start at zero and be continuous
    if (!list_empty(generation_list)) {
        previous = list_last_entry(generation_list, struct generation, list);
        sequence_number = previous->sequence_number + 1;
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

    generation->sequence_number = sequence_number;
    generation->session_type = session_type;

    generation->max_pdu_size = max_pdu_size;

    generation->next_pivot = 0;
    generation->coding_matrix_dimension = generation_size;

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


int generation_space_remaining(const generation_t* generation) {
    int size;
    size = generation->coding_matrix_dimension - generation->next_pivot;
    assert(size >= 0 && size <= generation->coding_matrix_dimension && "generation space is out of bounds");
    return size;
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

static NCM_GENERATION_STATUS generation_next_encoded_frame(const generation_t* generation, size_t max_length, u8* buffer, size_t* length_encoded) {
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

    // TODO rlnc_block_encode fails if only one frame is contained in the generation, rlcn will always just deliver empty buffer (though with correct length)
    //    this ONLY happens with MOEPGF2 or MOEPGF4 [nothing above].
    length = rlnc_block_encode(generation->rlnc_block, buffer, max_length, flags);

    if (length < 0) {
        LOG(LOG_ERR, "generation_next_encoded_frame() failed, error message above!");
        return GENERATION_GENERIC_ERROR;
    }

    *length_encoded = length;

    return GENERATION_STATUS_SUCCESS;
}

NCM_GENERATION_STATUS generation_list_next_encoded_frame(const struct list_head* generation_list, size_t max_length, u8* buffer, size_t* length_encoded) {
    generation_t* generation;
    generation = list_first_entry(generation_list, generation_t, list);
    // TODO we would need to send out encoded frames for all not yet ACK generations, not just the "next" one.
    return generation_next_encoded_frame(generation, max_length, buffer, length_encoded);
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
        // TODO advance generation list => call generation_list_next_decoded again if it changed anything
        // TODO return generation_list_next_decoded(generation_list, max_length, buffer, length_decoded);
        return GENERATION_FULLY_TRAVERSED;
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

    return GENERATION_STATUS_SUCCESS;
}

NCM_GENERATION_STATUS generation_list_decoder_add_decoded(struct list_head* generation_list, u8* buffer, size_t length) {
    generation_t* generation;
    NCM_GENERATION_STATUS status;

    list_for_each_entry(generation, generation_list, list) {
        // TODO for now we just use the first available generation,
        //  later we need to do this using the addressed generation of the extension header
        if (generation_space_remaining(generation) == 0) {
            continue;
        }

        status = generation_decoder_add_decoded(generation, buffer, length);

        return status;
    }

    return GENERATION_UNAVAILABLE;
}
