#ifndef __RLNC_H_
#define __RLNC_H_

#include <stdint.h>
#include <stdlib.h>

//#include "global.h"
#include <moepgf/moepgf.h>

/**
 * Flag used on `rlnc_block_encode`.
 * If flag is not defined, random linear encoding is used.
 * If flag is defined, the encoding is done in a structured way,
 * meaning, the frames are encoded in order, being sent out individually.
 * After every frame has been encoded once, random linear encoding is used.
 */
#define RLNC_STRUCTURED 0x1

/* Forward declaration for typedef */
struct rlnc_block;

/* Nobody should look inside an rlnc block */
typedef struct rlnc_block * rlnc_block_t;

/* Functions to init, free, and reset (zero-out memory, do not touch paramters
 * such as packet count, and to not deallocate/reallocate memory) */
rlnc_block_t	rlnc_block_init(int count, size_t dlen, size_t alignment,
						enum MOEPGF_TYPE gftype);
void		rlnc_block_free(rlnc_block_t b);
int		rlnc_block_reset(rlnc_block_t b);

/* Functions to add source frames, add/decode encoded frames, encode frames, and
 * get (return) decoded frames if available. */

/**
 * This function is called to add new sources frames to the given rlnc_block.
 * @param b - The `rlnc_block_t` the source frame should be added to.
 * @param pv - Pivot position of the added source frame.
 * @param data - Pointer to the data of the actual frame.
 * @param len - Length of the data.
 * @return -1 on an error, 0 on success.
 */
int 	rlnc_block_add(rlnc_block_t b, int pv, const uint8_t *data, size_t len);
int 	rlnc_block_decode(rlnc_block_t b, const uint8_t *src, size_t len);
ssize_t	rlnc_block_encode(const rlnc_block_t b, uint8_t *dst, size_t maxlen, int flags);
ssize_t	rlnc_block_get(rlnc_block_t b, int pv, uint8_t *dst, size_t maxlen);

/* Temporary helper functions that may become static in the future. */
void 	print_block(const rlnc_block_t b);

/**
 * Returns the rank of the encoding matrix.
 * @param b - The `rlnc_block_t` used to query.
 */
int	rlnc_block_rank_encode(const rlnc_block_t b);
/**
 * Returns the rank of the decoding matrix.
 * @param b - The `rlnc_block_t` used to query.
 */
int	rlnc_block_rank_decode(const rlnc_block_t b);
/**
 * Returns the maximum frame length currently contained in the matrix.
 * The frame length include coding vector length plus data vector length.
 * @param b - The `rlnc_block_t` used to query.
 */
ssize_t	rlnc_block_current_frame_len(const rlnc_block_t b);

#endif
