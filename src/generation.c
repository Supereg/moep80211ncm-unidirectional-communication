//
// Created by Andreas Bauer on 22.02.21.
//

#include "generation.h"

#include <assert.h>

#include <moepcommon/list.h>
#include <moepcommon/util.h>
#include <moepcommon/timeout.h>
#include <moeprlnc/rlnc.h>

#include "session.h"

#define LOG_GENERATION(loglevel, generation, message, ...) \
do { \
	LOG(loglevel, \
		message " [gen_seq=%d]", \
		##__VA_ARGS__, \
		generation->sequence_number); \
} while (0)

#define DIE_GENERATION(generation, message, ...) \
do { \
	DIE(message " [gen_seq=%d]", \
		##__VA_ARGS__, \
		generation->sequence_number); \
} while (0)

// Forward declaration for our timer callbacks. See `timeout_cb_t` type.
static int
generation_tx_callback(timeout_t timeout, u32 overrun, void* data);

/**
 * Struct containing all state information for sessions
 * which do transmission (SOURCE and INTERMEDIATE).
 */
struct tx {
	/**
	 * Counts the "created" frames.
	 * Thus this counter is only applciable for SOURCE nodes.
	 */
	int src_count;
	/**
	 * Counts the (based on link estimation)
	 * redundant transmissions.
	 */
	double redundancy;

	/**
	 * Transmission timeout.
	 * Runs with 0ms when we are sure we are transmitting linear independent
	 * information. Otherwise the timeout will increase for every
	 * (presumably) linear dependent transmission.
	 * See `tx_inc`, `tx_dec`, `tx_timeout_val`
	 */
	timeout_t timeout;
};

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
	 */
	u16 sequence_number;
	/**
	 * The index of the generation in the list, which
	 * the generation is inserted in.
	 */
	int index;

	/**
	 * The session type of the associated session (See `SESSION_TYPE`):
	 */
	const enum SESSION_TYPE session_type;

	rlnc_block_t rlnc_block;

	const generation_event_handler event_handler;
	void* event_data;

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

	/**
	 * Pointer to `tx` struct, holding state for nodes doing transmission.
	 * This pointer is NULL for nodes not doing any transmissions.
	 */
	struct tx* tx;

	/**
	 * struct for statistics
	 */
	struct generation_packet_counter ctr;
};

generation_t*
generation_find(struct list_head* generation_list, u16 sequence_number)
{
	generation_t* generation;

	list_for_each_entry (generation, generation_list, list) {
		if (generation->sequence_number == sequence_number) {
			return generation;
		}
	}

	return NULL;
}

generation_t*
generation_init(struct list_head* generation_list,
	enum SESSION_TYPE session_type,
	enum MOEPGF_TYPE moepgf_type,
	int generation_size,
	size_t max_pdu_size,
	size_t alignment,
	generation_event_handler event_handler,
	void* event_data)
{
	struct generation* generation;
	struct generation* previous;
	struct tx* tx;
	int ret;

	tx = NULL;
	u16 sequence_number = 0;
	int generation_index = 0;

	// As of time of writing (March 2021) rlnc_block_encode() fails to do encoding
	// [the resulting buffer will not be written to, length is properly set]
	// for generations with only one source frame and RLNC_STRUCTURED NOT set.
	// The issue seemingly doesn't occur with bigger GF types.
	// Thus we currently disallow those GF types!
	// Issue was reported via Mail to the NC team.
	assert(moepgf_type != MOEPGF2 && moepgf_type != MOEPGF4
		&& "Unable to init with MOEPGF2/MOEPGF4 as there are seemingly issues with libmoepgf");

	// generate next sequence number, required to start at zero and be continuous
	if (!list_empty(generation_list)) {
		previous = list_last_entry(
			generation_list, struct generation, list);

		sequence_number = previous->sequence_number + 1;
		assert(sequence_number <= GENERATION_MAX_SEQUENCE_NUMBER - 1);

		generation_index = previous->index + 1;
	}

	generation = calloc(1, sizeof(struct generation));
	if (generation == NULL) {
		DIE("generation_init() Failed to calloc() generation: %s [gen_seq=%d]",
			strerror(errno),
			sequence_number);
	}

	generation->sequence_number = sequence_number;
	generation->index = generation_index;

	*(enum SESSION_TYPE*)&generation->session_type = session_type;
	*(size_t*)&generation->max_pdu_size = max_pdu_size;
	*(int*)&generation->generation_size = generation_size;

	generation->rlnc_block = rlnc_block_init(
		generation_size, max_pdu_size, alignment, moepgf_type);
	if (generation->rlnc_block == NULL) {
		free(generation);
		DIE("generation_init() Failed to rlnc_block_init(): %s [gen_seq=%d]",
			strerror(errno),
			sequence_number);
	}

	*(generation_event_handler*)&generation->event_handler = event_handler;
	generation->event_data = event_data;

	generation->next_pivot = 0;
	generation->remote_dimension = 0;

	if (session_type == SOURCE || session_type == INTERMEDIATE) {
		tx = calloc(1, sizeof(struct tx));
		if (tx == NULL) {
			free(generation);
			DIE("generation_init() Failed to calloc() tx state: %s [gen_seq=%d]",
				strerror(errno),
				sequence_number);
		}

		ret = timeout_create(CLOCK_MONOTONIC,
			&tx->timeout,
			generation_tx_callback,
			generation);
		if (ret != 0) {
			generation_free(generation);
			DIE("generation_init() Failed to timeout_create() for tx timer: %s [gen_seq=%d]",
				strerror(errno),
				sequence_number);
		}

		tx->src_count = 0;
		tx->redundancy = 0.0;
	}

	generation->tx = tx;

	list_add_tail(&generation->list, generation_list);

	return generation;
}

void
generation_free(generation_t* generation)
{
	int ret;

	generation->next_pivot = 0;
	generation->remote_dimension = 0;

	rlnc_block_free(generation->rlnc_block);

	if (generation->tx != NULL) { // not present on DESTINATION nodes
		ret = timeout_delete(generation->tx->timeout);
		if (ret != 0) {
			DIE("Failed generation_free() to timeout_delete(): %s",
				strerror(errno));
		}

		free(generation->tx);
	}

	free(generation);
}

void
generation_list_free(struct list_head* generation_list)
{
	struct generation *current, *tmp;

	list_for_each_entry_safe (current, tmp, generation_list, list) {
		list_del(&current->list);
		generation_free(current);
	}
}

static void
generation_trigger_event(generation_t* generation,
	enum GENERATION_EVENT event,
	void* result)
{
	if (generation->event_handler != NULL) {
		generation->event_handler(
			generation, event, generation->event_data, result);
	}
}

static double
tx_estimation(const generation_t* generation)
{
	assert(generation->tx != NULL);
	return (double)generation->tx->src_count + generation->tx->redundancy;
}

/**
 * Function is called to count the creation(SOURCE)/received(INTERMEDIATE)
 * of a source frame.
 */
static void
tx_dec(generation_t* generation)
{
	struct tx* tx;
	assert(generation->tx != NULL);
	tx = generation->tx;

	if (tx_estimation(generation) >= 0) {
		tx->src_count = 0;
		tx->redundancy = 0.0;
	}

	// default value when no event handler is defined
	double session_redundancy = 1.0;

	generation_trigger_event(generation,
		GENERATION_EVENT_SESSION_REDUNDANCY,
		&session_redundancy);

	assert(session_redundancy >= 1);

	if (generation->session_type == SOURCE) {
		tx->src_count -= 1;
		// we subtract 1 as it is counted via src_count
		tx->redundancy -= session_redundancy - 1.0;
	} else if (generation->session_type == INTERMEDIATE) {
		tx->redundancy -= session_redundancy;
	}
}

/**
 * Function is called to count a transmission of a coded frame.
 */
static void
tx_inc(generation_t* generation)
{
	struct tx* tx;
	assert(generation->tx != NULL);
	tx = generation->tx;

	if (tx->src_count < 0) {
		tx->src_count += 1;
		// count transmission on sender side
		generation->ctr.data += 1;
	} else {
		// redundant transmission
		tx->redundancy += 1;
		// count redundant transmission on sender side
		generation->ctr.redundant += 1;
	}
}

static int
tx_timeout_val(const generation_t* generation)
{
	double time;

	if (tx_estimation(generation) <= -1) {
		time = 0;
	} else {
		time = GENERATION_RTX_MIN_TIMEOUT;
		time += generation_index(generation);

		// +1 as estimation in range of (-1;+infty) in this block
		time += tx_estimation(generation) + 1.0;

		time = min(time, (double)GENERATION_RTX_MAX_TIMEOUT);
	}

	return (int)time;
}

static void
generation_timeout_tx_schedule(generation_t* generation)
{
	assert(generation->tx != NULL);

	int ret;
	ret = timeout_settime(generation->tx->timeout,TIMEOUT_FLAG_SHORTEN,
		timeout_msec(tx_timeout_val(generation), 0));

	if (ret != 0) {
		DIE_GENERATION(generation,
			"generation_timeout_tx_schedule() failed timeout_settime(): %s",
			strerror(errno));
	}
}

static void
generation_timeout_tx_reset(generation_t* generation)
{
	int ret;

	if (generation->tx == NULL) {
		return;
	}

	ret = timeout_clear(generation->tx->timeout);

	if (ret != 0) {
		DIE_GENERATION(generation,
			"generation_timeout_tx_reset() failed timeout_clear(): %s",
			strerror(errno));
	}
}

bool
generation_empty(const generation_t* generation)
{
	return generation->next_pivot == 0;
}

int
generation_space_remaining(const generation_t* generation)
{
	int size;
	size = generation->generation_size - generation->next_pivot;
	assert(size >= 0 && size <= generation->generation_size);
	return size;
}

int
generation_list_space_remaining(struct list_head* generation_list)
{
	generation_t* generation;
	int count = 0;

	list_for_each_entry (generation, generation_list, list) {
		count += generation_space_remaining(generation);
	}

	return count;
}

bool
generation_is_complete(const generation_t* generation)
{
	switch (generation->session_type) {
	case SOURCE:
	case DESTINATION:
		// fully acknowledged && sent (SOURCE)
		// fully received && decoded (DESTINATION)
		return generation->remote_dimension >= generation->generation_size
		       && generation_space_remaining(generation) == 0;
	case INTERMEDIATE:
		// TODO explicitly support intermediate nodes
		DIE_GENERATION(generation, "Intermediate nodes are currently unsupported!");
	}

	DIE_GENERATION(generation, "Reached unsupported session type %d!",
		generation->session_type);
}

bool
generation_remote_decoded(const generation_t* generation)
{
	return generation->remote_dimension >= generation->next_pivot;
}

bool
generation_list_remote_decoded(struct list_head* generation_list)
{
	generation_t* generation;
	bool result = true;

	list_for_each_entry (generation, generation_list, list) {
		if (!generation_remote_decoded(generation)) {
			result = false;
			break;
		}
	}

	return result;
}

void
generation_update_remote_dimension(generation_t* generation, int dimension)
{
	// we only update the dimension if its bigger
	// to protect against stale ACK frames.
	if (dimension > generation->remote_dimension) {
		generation->remote_dimension = dimension;
	}

	if (generation_remote_decoded(generation)) {
		generation_timeout_tx_reset(generation);
	}
}

void
generation_assume_complete(generation_t* generation)
{
	generation_update_remote_dimension(generation, generation->generation_size);
	generation->next_pivot = generation->generation_size;
}

struct generation_packet_counter*
generation_get_counters(generation_t* generation)
{
	return &generation->ctr;
}

static void
generation_rewrite_indices(struct list_head* generation_list)
{
	generation_t* current;
	int index = 0;

	list_for_each_entry (current, generation_list, list) {
		current->index = index++;
	}
}

void
generation_reset(generation_t* generation, u16 new_sequence_number)
{
	int ret;

	generation_trigger_event(generation, GENERATION_EVENT_RESET, NULL);

	ret = rlnc_block_reset(generation->rlnc_block);
	if (ret != 0) {
		DIE_GENERATION(generation, "Failed to reset rlnc block, when trying to reset generation!");
	}

	generation->sequence_number = new_sequence_number;

	generation->next_pivot = 0;
	generation->remote_dimension = 0;

	generation_timeout_tx_reset(generation);
}

/**
 * Traverses through the whole list of generations to clean out completed generations
 * (generations which were sent out and successfully received at the other end).
 * The generation list is ordered by generation state, generations which are
 * currently worked on are at the beginning (as we add new source
 * frames iteratively), thus unused generations are at the end.
 * Once a generation (from the beginning of the list) is reset,
 * the generation list is shifted accordingly, such that the freed generations
 * (after getting the next free sequence number set) are at the end of the list.
 *
 * @param generation_list - The list of `generation`s to traverse.
 * @return Returns the amount of generations which got reset
 * 	as they were complete (and thus got moved to the beginning of the list).
 */
int
generation_list_advance(struct list_head* generation_list)
{
	generation_t* next;
	generation_t* last;
	u16 next_sequence_number;
	int advance_count = 0;

	for (;;) {
		next = list_first_entry(
			generation_list, struct generation, list);
		last = list_last_entry(
			generation_list, struct generation, list);

		if (!generation_is_complete(next)) {
			break;
		}

		next_sequence_number = (u16)last->sequence_number + 1;
		// reset generation initializing it with a new sequence number
		generation_reset(next, next_sequence_number);
		// moves the reset generation to the end of the list
		list_rotate_left(generation_list);

		advance_count++;
	}

	generation_rewrite_indices(generation_list);

	return advance_count;
}

static NCM_GENERATION_STATUS
generation_encoder_add(generation_t* generation, u8* buffer, size_t length)
{
	int ret;

	if (generation->session_type != SOURCE) {
		return GENERATION_GENERIC_ERROR;
	}

	if (length > generation->max_pdu_size) {
		return GENERATION_PACKET_TOO_LARGE;
	}

	if (generation_space_remaining(generation) == 0) {
		// matrix is full, can't add any further source frames
		return GENERATION_FULLY_TRAVERSED;
	}

	ret = rlnc_block_add(
		generation->rlnc_block, generation->next_pivot, buffer, length);
	if (ret != 0) {
		LOG_GENERATION(LOG_ERR, generation, "rlnc_block_decode() failed!");
		return GENERATION_GENERIC_ERROR;
	}

	generation->next_pivot++;
	tx_dec(generation);

	generation_timeout_tx_schedule(generation);

	return 0;
}

NCM_GENERATION_STATUS
generation_list_encoder_add(struct list_head* generation_list,
	u8* buffer,
	size_t length)
{
	generation_t* generation;
	NCM_GENERATION_STATUS status;

	list_for_each_entry (generation, generation_list, list) {
		if (generation_space_remaining(generation) == 0) {
			continue;
		}

		status = generation_encoder_add(generation, buffer, length);
		if (status != 0) {
			DIE_GENERATION(generation,
				"generation_list_encoder_add() failed to add buffer(%zu): %d",
				length,
				status);
		}

		return GENERATION_STATUS_SUCCESS;
	}

	LOG(LOG_WARNING, "All generations are full, dropping first generation");

	// no more space available. Discard a generation and shift to make space
	generation = list_first_entry(generation_list, generation_t, list);
	generation_assume_complete(generation);
	if (!(generation_list_advance(generation_list) > 0)) {
		return GENERATION_UNAVAILABLE;
	}

	// put packet in one of the newly freed generations
	return generation_list_encoder_add(generation_list, buffer, length);
}

NCM_GENERATION_STATUS
generation_next_encoded_frame(generation_t* generation,
	size_t max_length,
	u16* generation_sequence,
	u8* buffer,
	size_t* length_encoded)
{
	int flags = 0;
	ssize_t length;

	if (generation_empty(generation)) {
		return GENERATION_EMPTY;
	}

	if (generation->session_type == SOURCE) {
		// if its the source node (aka not the forwarder) we want
		// to send out the frame in a structured way.
		flags |= RLNC_STRUCTURED;
	}

	length = rlnc_block_encode(generation->rlnc_block,
		buffer,
		max_length,
		flags);

	if (length < 0) {
		LOG_GENERATION(LOG_ERR, generation,
			"generation_next_encoded_frame() failed, error message above!");
		return GENERATION_GENERIC_ERROR;
	}

	*generation_sequence = generation->sequence_number;
	*length_encoded = length;

	return GENERATION_STATUS_SUCCESS;
}

static NCM_GENERATION_STATUS
generation_next_decoded(generation_t* generation,
	size_t max_length,
	u8* buffer,
	size_t* length_decoded)
{
	ssize_t length;

	assert(generation->session_type != SOURCE && "Cannot decode from SOURCE session!");

	if (generation_space_remaining(generation) == 0) {
		return GENERATION_FULLY_TRAVERSED; // generation is already drained
	}

	length = rlnc_block_get(generation->rlnc_block,
		generation->next_pivot,
		buffer,
		max_length);
	if (length < 0) { // the destination buffer was probably too small!
		LOG_GENERATION(LOG_ERR, generation,
			"generation_next_decoded() failed as rlnc_block_get() failed, see above!");
		return GENERATION_GENERIC_ERROR;
	}

	if (length == 0) { // no bytes read, the given pivot can't be decoded
		return GENERATION_NOT_YET_DECODABLE;
	}

	generation->next_pivot++;
	*length_decoded = length;

	return GENERATION_STATUS_SUCCESS;
}

NCM_GENERATION_STATUS
generation_list_next_decoded(struct list_head* generation_list,
	size_t max_length,
	u8* buffer,
	size_t* length_decoded)
{
	generation_t* generation;
	NCM_GENERATION_STATUS status;
	int advanced_num;

	assert(!list_empty(generation_list)
		&& "generation list cannot be empty");

	for (;;) {
		generation = list_first_entry(generation_list, struct generation, list);

		status = generation_next_decoded(
			generation, max_length, buffer, length_decoded);

		// first entry in list is fully decoded
		if (status == GENERATION_FULLY_TRAVERSED) {
			advanced_num = generation_list_advance(generation_list);
			if (advanced_num > 0) {
				// we just reset the full generation,
				// check if there is still decoded data
				continue;
			}
		}

		return status;
	}
}

static NCM_GENERATION_STATUS
generation_decoder_add(generation_t* generation, u8* buffer, size_t length)
{
	int ret;

	if (length > generation->max_pdu_size) {
		return GENERATION_PACKET_TOO_LARGE;
	}

	/*
	 * No need for special checks, encoded packets can be added anytime:
	 * - Either the packet is linear independent
	 * 	=> this guarantees the coding matrix rank is not full
	 * - or the packet is linear dependent
	 * 	=> it is eliminated anyway
	 */

	ret = rlnc_block_decode(generation->rlnc_block, buffer, length);
	if (ret != 0) {
		LOG_GENERATION(
			LOG_ERR, generation, "rlnc_block_decode() failed!");
		return GENERATION_GENERIC_ERROR;
	}

	// we know for a fact, the remote dimension must equal
	// to the rank of what we have received
	generation_update_remote_dimension(generation,
		rlnc_block_rank_decode(generation->rlnc_block));

	if (generation->session_type == INTERMEDIATE) {
		tx_dec(generation);
		// TODO trigger a tx if not fully decoded?
	} else if (generation->session_type == DESTINATION) {
		generation_trigger_event(generation, GENERATION_EVENT_ACK, NULL);
		// count sent ack on receiver side
		generation->ctr.ack += 1;
	}

	return GENERATION_STATUS_SUCCESS;
}

void
align_generation_window(struct list_head* generation_list,
	coded_packet_metadata_t* metadata)
{
	u16 local_window_id;
	u16 window_id_delta;
	generation_t* entry;

	// see comments below for this requirement!
	assert(generation_window_size(generation_list) >= 2);

	local_window_id = generation_window_id(generation_list);

	window_id_delta = min(
		delta(metadata->window_id,
			local_window_id,
			GENERATION_MAX_SEQUENCE_NUMBER),
		delta(local_window_id,
			metadata->window_id,
			GENERATION_MAX_SEQUENCE_NUMBER)
	);

	if (window_id_delta != 0) {
		// we need to somehow determine if the remote window_id
		// is smaller or bigger than the local one!

		// TODO reengineer that such that it doesn't rely on the
		//  window size.
		if (window_id_delta >= metadata->window_size) {
			// we have non overlapping generation windows!
			// as sequence numbers are uint16 and wrap around,
			// we CAN't tell which window_id is bigger
			// (which is required for our adjustment logic below!
			// Solution would be to "magically" adjust the window
			// such that are equal again. In production environment
			// this strategy would need to protect against DOS
			// attacks. This is all out of the scope of the project.
			// Thus we just DIE. Reaching this point means something
			// has gone FATALLY wrong, anyways!
			DIE("FATAL generation_list_receive_frame() non overlapping generation windows!");
		}

		// our window_id is smaller, if the remote window_id is
		// contained in our current generation window!
		// We checked non equality AND overlapping windows above!
		// Those two assumptions are key for our logic to work!
		if (NULL != generation_find( generation_list, metadata->window_id)) {
			// the remote window is further ahead.
			// If we are a SOURCE this means we probably
			// lost some ACK packet.
			// If we are a DESTINATION the SOURCE probably
			// dropped a generation. The SOURCE has moved on and
			// won't send frames for "old" generations.
			// In both cases we move our generation window
			// to be equal with the remote.
			//
			// We IGNORE the case when local window is
			// further ahead (probably stale packets).
			// If we are a SOURCE, DESTINATION will reach this
			// case here when we send out next coded packet.
			// If we are DESTINATION, SOURCE will probably send a
			// coded frame for a generation we already have cleared.
			// We cover that in generation_list_receive_coded()
			// triggering a ACK if we can't find the generation
			// for a given coded packet.

			// sanity checking that we don't have
			// double overlapping windows
			// (happens if you choose too big generation window)
			assert(NULL == generation_find(
			       generation_list, metadata->window_id + metadata->window_size));

			list_for_each_entry (entry, generation_list, list) {
				if (entry->sequence_number == metadata->window_id) {
					break;
				}

				generation_assume_complete(entry);
			}

			// now ensure that the list is ordered again!
			(void)generation_list_advance(generation_list);
		}
	}
}

static NCM_GENERATION_STATUS
generation_list_receive_coded(struct list_head* generation_list,
	coded_packet_metadata_t* metadata,
	u8* buffer,
	size_t length)
{
	generation_t* generation;
	NCM_GENERATION_STATUS status;

	generation = generation_find(
		generation_list, metadata->generation_sequence);
	if (generation == NULL) {
		LOG(LOG_WARNING,
			"Received a seemingly late packet for the generation seq=%d",
			metadata->generation_sequence);
		// TODO this might not entirely work with Intermediate nodes
		//  (they shouldn't blindly ACK)?

		// to trigger event, we need a reference to some generation.
		// as ACKs are sent for all active generations, it's actually
		// irrelevant which generation the pointer references.
		assert(!list_empty(generation_list));
		generation = list_first_entry(generation_list, struct generation, list);

		// as align_generation_window() is assumed to have been called,
		// this is probably the case of a LOST ack for
		// the (last) fully decoded generation.
		// Thus we just send another ACK so the source can
		// free its side as well!
		generation_trigger_event(generation, GENERATION_EVENT_ACK, NULL);
		return GENERATION_UNAVAILABLE;
	}

	status = generation_decoder_add(generation, buffer, length);

	return status;
}

static NCM_GENERATION_STATUS
generation_list_receive_ack(struct list_head* generation_list,
	coded_packet_metadata_t* metadata,
	u8* buffer,
	size_t length)
{
	int count;
	ack_payload_t* ack_payloads;
	ack_payload_t ack;
	generation_t* generation;

	ack_payloads = (ack_payload_t*)buffer;
	count = (int)(length / sizeof(ack_payload_t));

	if (count != metadata->window_size) {
		LOG(LOG_ERR,
			"Inconsistent ACK length: entries=%d; window_size=%zu",
			count,
			length);
	}

	for (int i = 0; i < count; i++) {
		ack = ack_payloads[i];
		generation = generation_find(generation_list, ack.sequence_number);
		if (generation == NULL) {
			continue;
		}

		generation_update_remote_dimension(generation, ack.receiver_dim);
	}

	(void)generation_list_advance(generation_list);
	return 0;
}

NCM_GENERATION_STATUS
generation_list_receive_frame(struct list_head* generation_list,
	coded_packet_metadata_t* metadata,
	u8* buffer,
	size_t length)
{
	NCM_GENERATION_STATUS status;

	// Check for unequal window_ids (does implicit ACKs through the window_id)
	align_generation_window(generation_list, metadata);

	if (metadata->ack) {
		status = generation_list_receive_ack(
			generation_list, metadata, buffer, length);
	} else {
		status = generation_list_receive_coded(
			generation_list, metadata, buffer, length);
	}

	return status;
}

void
generation_write_ack_payload(struct list_head* generations_list,
	ack_payload_t* payload)
{
	struct generation* cur;
	int payload_ind;

	payload_ind = 0;
	list_for_each_entry (cur, generations_list, list) {
		payload[payload_ind].sequence_number = cur->sequence_number;
		payload[payload_ind].receiver_dim = cur->remote_dimension;
		payload_ind++;
	}
}

int
generation_window_size(struct list_head* generations_list)
{
	generation_t *first, *last;
	u16 delta;

	first = list_first_entry(generations_list, struct generation, list);
	last = list_last_entry(generations_list, struct generation, list);

	delta = delta(last->sequence_number,
		first->sequence_number,
		GENERATION_MAX_SEQUENCE_NUMBER);
	return delta + 1;
}

u16
generation_window_id(struct list_head* generations_list)
{
	generation_t* first;
	assert(!list_empty(generations_list)
		&& "Can't retrieve window_id for emtpy generation list!");

	first = list_first_entry(generations_list, struct generation, list);

	return first->sequence_number;
}

int
generation_index(const generation_t* generation)
{
	return generation->index;
}

static int
generation_tx_callback(timeout_t timeout, u32 overrun, void* data)
{
	(void)timeout;
	(void)overrun;
	generation_t* generation;
	int transmissions;

	generation = data;

	if (generation_remote_decoded(generation)) {
		return 0;
	}
	if (generation_is_complete(generation)) {
		return 0;
	}

	if (overrun) {
		LOG_GENERATION(LOG_WARNING, generation,
			"generation_tx_callback() detected %d skipped transmissions (overruns)",
			overrun);
	}

	transmissions = (int)overrun + 1;

	do {
		generation_trigger_event(generation, GENERATION_EVENT_ENCODED, NULL);
		tx_inc(generation);

		if (transmissions > 0) {
			transmissions--;
		}
	} while (tx_timeout_val(generation) < GENERATION_RTX_MIN_TIMEOUT
		 || transmissions > 0);

	// as a timeout, we rely on the session destroy timer
	generation_timeout_tx_schedule(generation);

	return 0;
}
