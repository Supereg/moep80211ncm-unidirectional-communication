// This file contains all test case definitions related to the `generation.c` file.
// The generation test `Suite` is created inside `generation_suite()`.
//
// To add any tests, use `START_TEST(...)` and `END_TEST` marcos,
// then modify `generation_suite()` accordingly, so that `tcase_add_test` is called
// to add the test to a given test case.
//
// Created by Andreas Bauer on 22.02.21.
//

#include <stdio.h>
#include <check.h>

#include <moepcommon/list.h>

#include "check_simulator.h"
#include "../src/generation.h"
#include "../src/generation.c"

static LIST_HEAD(check_generation_list);
static LIST_HEAD(check_generation_list0);


/**
 * Setup is called before **every** test of a `TCase` (Test case).
 * It must be registered to the `TCase` using `tcase_add_checked_fixture`.
 */
void test_generation_setup() {

}

/**
 * Teardown is called after **every** test of a `TCase` (Test case).
 * It must be registered to the `TCase` using `tcase_add_checked_fixture`.
 */
void test_generation_teardown() {
    generation_list_free(&check_generation_list);
    generation_list_free(&check_generation_list0);
}

/* ----------------------------------- Basic Setup Tests ----------------------------------- */

START_TEST(test_generation_creation) {
    generation_t* generation0;
    generation_t* loop_generation;

    // basic generation init checks
    generation0 = generation_init(&check_generation_list, SOURCE, CHECK_GF_TYPE, CHECK_GENERATION_SIZE, CHECK_MAX_PDU, CHECK_ALIGNMENT);
    ck_assert_int_eq(generation0->sequence_number, 0);
    ck_assert_int_eq(generation0->session_type, SOURCE);
    ck_assert_int_eq(generation0->generation_size, CHECK_GENERATION_SIZE);
    ck_assert_int_eq(generation0->max_pdu_size, CHECK_MAX_PDU);
    ck_assert_int_eq(generation0->next_pivot, 0);

    ck_assert_int_eq(generation_space_remaining(generation0), CHECK_GENERATION_SIZE);

    for (int i = 1; i < 10; i++) { // do some loops to check that sequence number is incremented properly
        loop_generation = generation_init(&check_generation_list, SOURCE, CHECK_GF_TYPE, CHECK_GENERATION_SIZE, CHECK_MAX_PDU, CHECK_ALIGNMENT);
        ck_assert_int_eq(loop_generation->sequence_number, i);
    }
}
END_TEST

/* ----------------------------------- CODING related tests ----------------------------------- */

START_TEST(test_generation_source) {
    generation_t* generation;
    NCM_GENERATION_STATUS  status;
    ssize_t returned_length;
    u8 buffer[CHECK_MAX_PDU] = {0};
    char* example0 = "Hello World!";
    char* example1 = "What Up???";

    generation = generation_init(&check_generation_list, SOURCE, CHECK_GF_TYPE, 1, CHECK_MAX_PDU, CHECK_ALIGNMENT);

    status = generation_encoder_add(generation, (u8*) buffer, CHECK_MAX_PDU + 1);
    ck_assert_int_eq(status, GENERATION_PACKET_TOO_LARGE);

    status = generation_encoder_add(generation, (u8*) example0, strlen(example0));
    ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);
    ck_assert_int_eq(generation->next_pivot, 1);
    ck_assert_int_eq(generation_space_remaining(generation), 0);

    returned_length = rlnc_block_get(generation->rlnc_block, 0, buffer, CHECK_MAX_PDU);
    ck_assert_int_eq(returned_length, strlen(example0));
    ck_assert_str_eq(example0, (char*) buffer);

    status = generation_encoder_add(generation, (u8*) example1, strlen(example1));
    ck_assert_int_eq(status, GENERATION_FULLY_TRAVERSED);
}
END_TEST

START_TEST(test_generation_destination) {
    generation_t* source;
    generation_t* destination;
    NCM_GENERATION_STATUS  status;
    u16 generation_sequence;
    size_t length;
    u8 buffer[CHECK_MAX_PDU] = {0};
    char* example0 = "Hello World!";

    source = generation_init(&check_generation_list, SOURCE, CHECK_GF_TYPE, 1, CHECK_MAX_PDU, CHECK_ALIGNMENT);
    destination = generation_init(&check_generation_list0, DESTINATION, CHECK_GF_TYPE, 1, CHECK_MAX_PDU, CHECK_ALIGNMENT);

    status = generation_next_encoded_frame(source, CHECK_MAX_PDU, &generation_sequence, buffer, &length);
    ck_assert_int_eq(status, GENERATION_EMPTY);
    status = generation_next_decoded(destination, CHECK_MAX_PDU, buffer, &length);
    ck_assert_int_eq(status, GENERATION_NOT_YET_DECODABLE);

    status = generation_encoder_add(source, (u8*) example0, strlen(example0));
    ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);

    status = generation_next_encoded_frame(source, CHECK_MAX_PDU, &generation_sequence, buffer, &length);
    ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);
    ck_assert_int_eq(generation_sequence, 0);

    status = generation_decoder_add_decoded(destination, buffer, length);
    ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);

    memset(buffer, 0, CHECK_MAX_PDU);

    status = generation_next_decoded(destination, CHECK_MAX_PDU, buffer, &length);
    ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);
    ck_assert_int_eq(length, strlen(example0));
    ck_assert_str_eq(example0, (char*) buffer);

    status = generation_next_decoded(destination, CHECK_MAX_PDU, buffer, &length);
    ck_assert_int_eq(status, GENERATION_FULLY_TRAVERSED);
}
END_TEST

START_TEST(test_generation_advance_source) {
    generation_t* source_gen0;
    generation_t* source_gen1;
    NCM_GENERATION_STATUS status;

    u8 buffer[CHECK_MAX_PDU] = {0};
    size_t length;
    coded_packet_metadata_t metadata;

    char* example0 = "Hello World!";
    char* example1 = "Hello World2!";
    char* example2 = "Hello World3!";

    source_gen0 = generation_init(&check_generation_list, SOURCE, CHECK_GF_TYPE, 2, CHECK_MAX_PDU, CHECK_ALIGNMENT);
    ck_assert_int_eq(source_gen0->sequence_number, 0);
    // TODO check_generation_list0
    source_gen1 = generation_init(&check_generation_list, SOURCE, CHECK_GF_TYPE, 2, CHECK_MAX_PDU, CHECK_ALIGNMENT);
    ck_assert_int_eq(source_gen1->sequence_number, 1);

    status = generation_list_encoder_add(&check_generation_list, (u8*) example0, strlen(example0));
    ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);
    status = generation_list_encoder_add(&check_generation_list, (u8*) example1, strlen(example1));
    ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);

    // Call "generation_list_next_encoded_frame" two times to simulate sending them out (calling generation_advance)
    // TODO This is currently heavily built around the assumption that we have instant ACKs
    status = generation_list_next_encoded_frame(&check_generation_list, CHECK_MAX_PDU, &metadata, buffer, &length);
    ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);
    ck_assert_int_eq(metadata.generation_sequence, 0);
    status = generation_list_next_encoded_frame(&check_generation_list, CHECK_MAX_PDU, &metadata, buffer, &length);
    ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);
    ck_assert_int_eq(metadata.generation_sequence, 0);

    status = generation_list_encoder_add(&check_generation_list, (u8*) example2, strlen(example2));
    ck_assert_int_eq(status, GENERATION_STATUS_SUCCESS);

    // checking that indeed generation_advance properly shifter the list and cleaned out completed generation
    ck_assert_int_eq(source_gen0->sequence_number, 2);
    ck_assert_int_eq(source_gen0->next_pivot, 0);
    ck_assert_int_eq(source_gen0->remote_dimension, 0);


    memset(buffer, 0, CHECK_MAX_PDU);
    length = rlnc_block_get(source_gen1->rlnc_block, 0, buffer, CHECK_MAX_PDU);
    ck_assert_int_ge(length, 0);

    ck_assert_str_eq(example2, (char*) buffer);
}
END_TEST

// TODO test: simulating frames arriving out of order (+ across multiple generations)

/* -------------------------------------------------------------------------------------------- */

Suite* generation_suite() {
    Suite* suite;

    TCase* generation_handling;
    TCase* generation_coding;

    suite = suite_create("generation");

    generation_handling = tcase_create("Generation Creation");
    generation_coding = tcase_create("Generation Coding");

    tcase_add_checked_fixture(generation_handling, test_generation_setup, test_generation_teardown);
    tcase_add_test(generation_handling, test_generation_creation);

    tcase_add_checked_fixture(generation_coding, test_generation_setup, test_generation_teardown);
    tcase_add_test(generation_coding, test_generation_source);
    tcase_add_test(generation_coding, test_generation_destination);
    tcase_add_test(generation_coding, test_generation_advance_source);

    suite_add_tcase(suite, generation_handling);
    suite_add_tcase(suite, generation_coding);

    return suite;
}
