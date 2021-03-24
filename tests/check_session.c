// This file contains all test case definitions related to the `session.c` file.
// The session test `Suite` is created inside `session_suite()`.
//
// To add any tests, use `START_TEST(...)` and `END_TEST` marcos,
// then modify `session_suite()` accordingly, so that `tcase_add_test` is called
// to add the test to a given test case.
//
// Created by Andreas Bauer on 22.02.21.
//

#include "check_suites.h"
#include "check_utils.h"

#include <stdio.h>
#include <check.h>

#include <moepcommon/util.h>

#include "../src/session.c" // NOLINT(bugprone-suspicious-include)

static u8 address_src[IEEE80211_ALEN] = {0x41, 0x41, 0x41, 0x41, 0x41, 0x41};
static u8 address_intermediate[IEEE80211_ALEN] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
static u8 address_dst[IEEE80211_ALEN] = {0x43, 0x43, 0x43, 0x43, 0x43, 0x43};

session_subsystem_context_t* src_context;
session_subsystem_context_t* intermediate_context;
session_subsystem_context_t* dst_context;

/**
 * Setup is called before **every** test of a `TCase` (Test case).
 * It must be registered to the `TCase` using `tcase_add_checked_fixture`.
 */
void test_session_setup() {
    init_check_utils();

    src_context = session_subsystem_init(
        CHECK_GENERATION_SIZE,
        CHECK_GENERATION_WINDOW_SIZE,
        CHECK_GF_TYPE,
        address_src,
        check_rtx_frame_callback,
        check_os_frame_callback);
    intermediate_context = session_subsystem_init(
        CHECK_GENERATION_SIZE,
        CHECK_GENERATION_WINDOW_SIZE,
        CHECK_GF_TYPE,
        address_intermediate,
        check_rtx_frame_callback,
        check_os_frame_callback);
    dst_context = session_subsystem_init(
        CHECK_GENERATION_SIZE,
        CHECK_GENERATION_WINDOW_SIZE,
        CHECK_GF_TYPE,
        address_dst,
        check_rtx_frame_callback,
        check_os_frame_callback);
}

/**
 * Teardown is called after **every** test of a `TCase` (Test case).
 * It must be registered to the `TCase` using `tcase_add_checked_fixture`.
 */
void test_session_teardown() {
    close_check_utils();

    session_subsystem_close(src_context);
    session_subsystem_close(intermediate_context);
    session_subsystem_close(dst_context);
}

/* ----------------------------------- Basic Setup Tests ----------------------------------- */

START_TEST(test_session_creation_and_find) {
    session_t* session;
    session_t* created_src_session;
    session_t* created_dst_session;
    session_t* created_intermediate_session;
    session_t* tmp_session;
    session_id expected_id;

    memcpy(expected_id.source_address, address_src, IEEE80211_ALEN);
    memcpy(expected_id.destination_address, address_dst, IEEE80211_ALEN);

    // testing that session is not yet created
    session = session_find(src_context, address_src, address_dst);
    ck_assert_msg(session == NULL, "Session list already contained session which is to be created!");

    // calling session_register on an unregistered session should create one
    created_src_session = session_register(src_context, address_src, address_dst);
    ck_assert_msg(created_src_session != NULL, "Failed session creation!");
    ck_assert_int_eq(created_src_session->type, SOURCE);
    ck_assert_mem_eq(&created_src_session->session_id, &expected_id, sizeof(session_id));

    // calling session_register on an registered session should just return that
    tmp_session = session_register(src_context, address_src, address_dst);
    ck_assert_msg(tmp_session == created_src_session, "Differing pointers to the same session!");

    // session_find for the inverse flow should not yield a result
    session = session_find(src_context, address_dst, address_src);
    ck_assert_msg(session == NULL, "After creating session, the other direction was weirdly also present!");

    // session_find for the created session should properly return that!
    session = session_find(src_context, address_src, address_dst);
    ck_assert_msg(session != NULL, "Failed to find created session!");
    ck_assert_msg(session == created_src_session, "Pointers to found session differ to the created one!");

    session_free(created_src_session);

    // now test creation of session for destination node
    created_dst_session = session_register(dst_context, address_src, address_dst);
    ck_assert_msg(created_dst_session != NULL, "Failed session creation!");
    ck_assert_int_eq(created_dst_session->type, DESTINATION); // testing proper session type detection
    ck_assert_mem_eq(&created_dst_session->session_id, &expected_id, sizeof(session_id));

    // now test creation of session for intermediate nodes
    created_intermediate_session = session_register(intermediate_context, address_src, address_dst);
    ck_assert_msg(created_intermediate_session != NULL, "Failed session creation!");
    ck_assert_int_eq(created_intermediate_session->type, INTERMEDIATE); // testing proper session type detection
    ck_assert_mem_eq(&created_intermediate_session->session_id, &expected_id, sizeof(session_id));
}
END_TEST

/* ----------------------------------- CODING related tests ----------------------------------- */

START_TEST(test_session_coding_simple_two_nodes) {
    check_test_context_t* context;
    session_t* source;
    session_t* destination;

    int ret;

    char* example0 = "Hello World!";
    char* example1 = "Hello World, whats up with you all?";
    char* example2 = "Hello World2!";

    os_frame_entry_t* received;

    // those configurations below are expected to successfully run the unit test
    *(int*) &src_context->generation_size = 2;
    *(int*) &src_context->generation_window_size = 2;
    *(int*) &dst_context->generation_size = 2;
    *(int*) &dst_context->generation_window_size = 2;

    source = session_register(src_context, address_src, address_dst);
    ck_assert_int_eq(source->type, SOURCE);

    destination = session_register(dst_context, address_src, address_dst);
    ck_assert_int_eq(destination->type, DESTINATION);
    ck_assert_mem_eq(&source->session_id, &destination->session_id, sizeof(session_id));

    // defines involved sessions, and forwarding behavior for the rtx callback (check_rtx_frame_callback)
    context = test_init(source, NULL, destination, 1.0, -1);

    ret = session_encoder_add(source, CHECK_ETHER_TYPE, (u8*) example0, strlen(example0));
    ck_assert_int_eq(ret, EXIT_SUCCESS);

    await_os_frame();

    // TODO shortcut to assert received packet
    received = peek_os_frame_entry(0);
    ck_assert_int_eq(received->length, strlen(example0));
    ck_assert_int_eq(received->ether_type, CHECK_ETHER_TYPE);
    ck_assert_str_eq((char*) received->payload, example0);

    ret = session_encoder_add(source, CHECK_ETHER_TYPE, (u8*) example1, strlen(example1));
    ck_assert_int_eq(ret, EXIT_SUCCESS);

    await_os_frame();

    received = peek_os_frame_entry(1);
    ck_assert_int_eq(received->length, strlen(example1));
    ck_assert_int_eq(received->ether_type, CHECK_ETHER_TYPE);
    ck_assert_str_eq((char*) received->payload, example1);

    // adding the third frame, will test if generation_list_advance works properly
    ret = session_encoder_add(source, CHECK_ETHER_TYPE, (u8*) example2, strlen(example2));
    ck_assert_int_eq(ret, EXIT_SUCCESS);

    await_os_frame();

    received = peek_os_frame_entry(2);
    ck_assert_int_eq(received->length, strlen(example2));
    ck_assert_int_eq(received->ether_type, CHECK_ETHER_TYPE);
    ck_assert_str_eq((char*) received->payload, example2);

    test_free(context);
}
END_TEST

// TODO packet loss tests + randomized packets tests (+multiple session_encoder_add per await_os_frame())

/* -------------------------------------------------------------------------------------------- */

Suite* session_suite() {
    Suite* suite;

    TCase* session_handling;
    TCase* session_coding;

    suite = suite_create("session");

    session_handling = tcase_create("Session Creation & Find");
    session_coding = tcase_create("Session Coding");

    tcase_add_checked_fixture(session_handling, test_session_setup, test_session_teardown);
    tcase_add_test(session_handling, test_session_creation_and_find);

    tcase_add_checked_fixture(session_coding, test_session_setup, test_session_teardown);
    tcase_add_test(session_coding, test_session_coding_simple_two_nodes);

    suite_add_tcase(suite, session_handling);
    suite_add_tcase(suite, session_coding);

    return suite;
}
