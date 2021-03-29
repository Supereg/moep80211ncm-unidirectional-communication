// This file contains all test case definitions related to the `generation.c` file.
// The generation test `Suite` is created inside `generation_suite()`.
//
// To add any tests, use `START_TEST(...)` and `END_TEST` marcos, then modify
// `generation_suite()` accordingly, so that `tcase_add_test` is called
// to add the test to a given test case.
//
// Created by Andreas Bauer on 22.02.21.
//

#include <stdio.h>
#include <check.h>

#include "check_suites.h"
#include "check_utils.h"

#include "../src/generation.h"
#include "../src/generation.c" // NOLINT(bugprone-suspicious-include)

static LIST_HEAD(check_generation_list);
static LIST_HEAD(check_generation_list0);

/**
 * Setup is called before **every** test of a `TCase` (Test case).
 * It must be registered to the `TCase` using `tcase_add_checked_fixture`.
 */
void
test_generation_setup()
{
	init_check_utils();
}

/**
 * Teardown is called after **every** test of a `TCase` (Test case).
 * It must be registered to the `TCase` using `tcase_add_checked_fixture`.
 */
void
test_generation_teardown()
{
	close_check_utils();

	generation_list_free(&check_generation_list);
	generation_list_free(&check_generation_list0);
}

static void
check_gen_event_handler(generation_t* generation,
	enum GENERATION_EVENT event,
	void* data,
	void* result)
{
	(void)generation;
	(void)data;
	(void)result;

	switch (event) {
	case GENERATION_EVENT_SESSION_REDUNDANCY: // implementation uses default "result" value
	case GENERATION_EVENT_ACK:
	case GENERATION_EVENT_ENCODED:
	case GENERATION_EVENT_RESET:
		break;
	default:
		DIE_GENERATION(generation,
			"Received unknown generation event: %d",
			event);
	}
}

static generation_t*
check_generation_init(struct list_head* generation_list,
	enum SESSION_TYPE type,
	int generation_size)
{
	return generation_init(generation_list,
		type,
		CHECK_GF_TYPE,
		generation_size,
		CHECK_MAX_PDU,
		CHECK_ALIGNMENT,
		check_gen_event_handler,
		NULL);
}

/* ---------------------------- Basic Setup Tests --------------------------- */

START_TEST(test_generation_creation)
{
	generation_t* generation0;
	generation_t* loop_generation;

	// basic generation init checks
	generation0 = check_generation_init(
		&check_generation_list, SOURCE, CHECK_GENERATION_SIZE);
	ck_assert_int_eq(generation0->sequence_number, 0);
	ck_assert_int_eq(generation0->session_type, SOURCE);
	ck_assert_int_eq(generation0->generation_size, CHECK_GENERATION_SIZE);
	ck_assert_int_eq(generation0->max_pdu_size, CHECK_MAX_PDU);
	ck_assert_int_eq(generation0->next_pivot, 0);

	ck_assert_int_eq(
		generation_space_remaining(generation0), CHECK_GENERATION_SIZE);

	// do some loops to check that sequence number is incremented properly
	for (int i = 1; i < 10; i++) {
		loop_generation = check_generation_init(
			&check_generation_list, SOURCE, CHECK_GENERATION_SIZE);
		ck_assert_int_eq(loop_generation->sequence_number, i);
		ck_assert_int_eq(generation_index(loop_generation), i);
	}
}
END_TEST

/**
 * This unit test checks if the UINT16 wrap around of the
 * generation sequence number is handled properly by
 * all relevant functions.
 */
START_TEST(test_generation_sequence_number)
{
	struct list_iterator iterator;
	struct list_iterator* iterator_ptr;
	generation_t *first, *entry;

	const int window_size = 4;
	const int seq_space = 6;
	const u16 start_seq = (GENERATION_MAX_SEQUENCE_NUMBER + 1) - seq_space;

	// create 4 generations in our generation list
	for (int i = 0; i < window_size; i++) {
		entry = check_generation_init(
			&check_generation_list, SOURCE, CHECK_GENERATION_SIZE);
		// move seq num to the end of the UINT16 window
		entry->sequence_number = start_seq + i;
	}

	for (int i = 0; i < 2 * seq_space; i++) {
		u16 seq_base = start_seq + i;

		ck_assert_int_eq(generation_window_size(&check_generation_list),
			window_size);
		ck_assert_uint_eq(generation_window_id(&check_generation_list),
			seq_base);

		first = list_first_entry(&check_generation_list, struct generation, list);

		int j = 0;
		iterator = list_get_iterator(&check_generation_list);
		iterator_ptr = &iterator;

		while (list_has_next(iterator_ptr)) {
			ck_assert_msg(j < window_size,
				"unexpected generation index of %d", j);

			u16 expected_seq = seq_base + j;
			entry = list_next_entry(iterator_ptr, struct generation, list);

			ck_assert_msg(entry->sequence_number == expected_seq,
				"seq=%d didn't match expected seq=%d at gen_index=%d",
				entry->sequence_number,
				expected_seq,
				j);

			ck_assert_int_eq(generation_index(entry), j);

			j++;
		}

		generation_assume_complete(first);
		generation_list_advance(&check_generation_list);
	}
}
END_TEST

/* -------------------------- CODING related tests -------------------------- */

START_TEST(test_generation_source)
{
	generation_t* generation;
	NCM_GENERATION_STATUS status;
	ssize_t returned_length;
	u8 buffer[CHECK_MAX_PDU] = { 0 };
	char* example0 = "Hello World!";
	char* example1 = "What Up???";

	generation = check_generation_init(&check_generation_list, SOURCE, 1);

	status = generation_encoder_add(
		generation, (u8*)buffer, CHECK_MAX_PDU + 1);
	ck_assert_int_eq(status, GENERATION_PACKET_TOO_LARGE);

	status = generation_encoder_add(
		generation, (u8*)example0, strlen(example0));
	ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);
	ck_assert_int_eq(generation->next_pivot, 1);
	ck_assert_int_eq(generation_space_remaining(generation), 0);

	returned_length = rlnc_block_get(
		generation->rlnc_block, 0, buffer, CHECK_MAX_PDU);
	ck_assert_int_eq(returned_length, strlen(example0));
	ck_assert_str_eq(example0, (char*)buffer);

	status = generation_encoder_add(
		generation, (u8*)example1, strlen(example1));
	ck_assert_int_eq(status, GENERATION_FULLY_TRAVERSED);

	generation_assume_complete(generation); // cancel tx timeout
}
END_TEST

START_TEST(test_generation_destination)
{
	generation_t* source;
	generation_t* destination;
	NCM_GENERATION_STATUS status;
	u16 generation_sequence;
	size_t length;
	u8 buffer[CHECK_MAX_PDU] = { 0 };
	char* example0 = "Hello World!";

	source = check_generation_init(&check_generation_list, SOURCE, 1);
	destination = check_generation_init(
		&check_generation_list0, DESTINATION, 1);

	status = generation_next_encoded_frame(
		source, CHECK_MAX_PDU, &generation_sequence, buffer, &length);
	ck_assert_int_eq(status, GENERATION_EMPTY);
	status = generation_next_decoded(
		destination, CHECK_MAX_PDU, buffer, &length);
	ck_assert_int_eq(status, GENERATION_NOT_YET_DECODABLE);

	status = generation_encoder_add(
		source, (u8*)example0, strlen(example0));
	ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);

	status = generation_next_encoded_frame(
		source, CHECK_MAX_PDU, &generation_sequence, buffer, &length);
	ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);
	ck_assert_int_eq(generation_sequence, 0);

	generation_assume_complete(source); // cancel tx timeout

	status = generation_decoder_add(destination, buffer, length);
	ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);

	memset(buffer, 0, CHECK_MAX_PDU);

	status = generation_next_decoded(
		destination, CHECK_MAX_PDU, buffer, &length);
	ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);
	ck_assert_int_eq(length, strlen(example0));
	ck_assert_str_eq(example0, (char*)buffer);

	status = generation_next_decoded(
		destination, CHECK_MAX_PDU, buffer, &length);
	ck_assert_int_eq(status, GENERATION_FULLY_TRAVERSED);
}
END_TEST

START_TEST(test_generation_advance_source)
{
	generation_t* source_gen0;
	generation_t* source_gen1;
	NCM_GENERATION_STATUS status;

	u8 buffer[CHECK_MAX_PDU] = { 0 };
	size_t length;
	u16 sequence_number;

	char* example0 = "Hello World!";
	char* example1 = "Hello World2!";
	char* example2 = "Hello World3!";

	source_gen0 = check_generation_init(&check_generation_list, SOURCE, 2);
	ck_assert_int_eq(source_gen0->sequence_number, 0);
	source_gen1 = check_generation_init(&check_generation_list, SOURCE, 2);
	ck_assert_int_eq(source_gen1->sequence_number, 1);

	status = generation_list_encoder_add(
		&check_generation_list, (u8*)example0, strlen(example0));
	ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);
	status = generation_list_encoder_add(
		&check_generation_list, (u8*)example1, strlen(example1));
	ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);

	// Call generation_next_encoded_frame() two times to simulate
	// sending them out (calling generation_advance)
	status = generation_next_encoded_frame(
		source_gen0, CHECK_MAX_PDU, &sequence_number, buffer, &length);
	ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);
	ck_assert_int_eq(sequence_number, 0);

	// simulate reception of ack frame
	generation_update_remote_dimension(
		source_gen0, source_gen0->remote_dimension + 1);
	generation_list_advance(&check_generation_list);

	status = generation_next_encoded_frame(
		source_gen0, CHECK_MAX_PDU, &sequence_number, buffer, &length);
	ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);
	ck_assert_int_eq(sequence_number, 0);

	// simulate reception of ack frame
	generation_update_remote_dimension(
		source_gen0, source_gen0->remote_dimension + 1);
	generation_list_advance(&check_generation_list);

	status = generation_list_encoder_add(
		&check_generation_list, (u8*)example2, strlen(example2));
	ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);

	// checking that indeed generation_advance properly shifter the list
	// and cleaned out completed generation
	ck_assert_int_eq(source_gen0->sequence_number, 2);
	ck_assert_int_eq(source_gen0->next_pivot, 0);
	ck_assert_int_eq(source_gen0->remote_dimension, 0);

	memset(buffer, 0, CHECK_MAX_PDU);
	length = rlnc_block_get(
		source_gen1->rlnc_block, 0, buffer, CHECK_MAX_PDU);
	ck_assert_int_ge(length, 0);

	ck_assert_str_eq(example2, (char*)buffer);

	generation_assume_complete(source_gen0); // cancel tx timeout
	generation_assume_complete(source_gen1); // cancel tx timeout
}
END_TEST

/* -------------------------------------------------------------------------- */

Suite*
generation_suite()
{
	Suite* suite;

	TCase* generation_handling;
	TCase* generation_coding;

	suite = suite_create("generation");

	generation_handling = tcase_create("Generation Creation");
	generation_coding = tcase_create("Generation Coding");

	tcase_add_checked_fixture(generation_handling,
		test_generation_setup,
		test_generation_teardown);
	tcase_add_test(generation_handling, test_generation_creation);
	tcase_add_test(generation_handling, test_generation_sequence_number);

	tcase_add_checked_fixture(generation_coding,
		test_generation_setup,
		test_generation_teardown);
	tcase_add_test(generation_coding, test_generation_source);
	tcase_add_test(generation_coding, test_generation_destination);
	tcase_add_test(generation_coding, test_generation_advance_source);

	suite_add_tcase(suite, generation_handling);
	suite_add_tcase(suite, generation_coding);

	return suite;
}
