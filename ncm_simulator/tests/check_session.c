// This file contains all test case definitions related to the `session.c` file.
// The session test `Suite` is created inside `session_suite()`.
//
// To add any tests, use `START_TEST(...)` and `END_TEST` marcos,
// then modify `session_suite()` accordingly, so that `tcase_add_test` is called
// to add the test to a given test case.
//
// Created by Andreas Bauer on 22.02.21.
//

#include <stdio.h>
#include <check.h>

#include <moepcommon/list.h>
#include <moepcommon/util.h>

#include "check_simulator.h"
#include "../src/session.h"
#include "../src/session.c"

static u8 address_a[IEEE80211_ALEN] = {0x41, 0x41, 0x41, 0x41, 0x41, 0x41};
static u8 address_b[IEEE80211_ALEN] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42};

session_subsystem_context* context;

/**
 * Used to store a call to the `rtx_callback` in order to make it available to the test case.
 */
typedef struct rtx_frame_entry {
    struct list_head list;
    int index;

    session_t* session;
    u8 payload[CHECK_MAX_PDU];
    size_t length;
} rtx_frame_entry_t;
static LIST_HEAD(rtx_frame_entries);

/**
 * Use to store a call to the `os_callback` in order to make it available to the test case.
 */
typedef struct os_frame_entry {
    struct list_head list;
    int index;

    session_t* session;
    u8 payload[CHECK_MAX_PDU];
    size_t length;
} os_frame_entry_t;
static LIST_HEAD(os_frame_entries);

// Bunch of forward declaration for the whole "callback storage" API
static int check_rtx_frame(session_t* session, u8* payload, size_t length);
static int check_os_frame(session_t* session, u8* payload, size_t length);
static rtx_frame_entry_t* pop_rtx_frame_entry(); // Don't forget to free(...) after pop
static os_frame_entry_t * pop_os_frame_entry(); // Don't forget to free(...) after pop
static rtx_frame_entry_t* peek_rtx_frame_entry(int index);
static os_frame_entry_t * peek_os_frame_entry(int index);
static void forward_frames(session_t* destination, int count, bool forward_from_source);
static void free_rtx_frame_entries();
static void free_os_frame_entries();


/**
 * Setup is called before **every** test of a `TCase` (Test case).
 * It must be registered to the `TCase` using `tcase_add_checked_fixture`.
 */
void test_session_setup() {
    context = init_session_subsystem();
    context->generation_size = CHECK_GENERATION_SIZE;
    context->generation_window_size = CHECK_GENERATION_WINDOW_SIZE;
    context->moepgf_type = CHECK_GF_TYPE;
    context->rtx_callback = check_rtx_frame;
    context->os_callback = check_os_frame;
}

/**
 * Teardown is called after **every** test of a `TCase` (Test case).
 * It must be registered to the `TCase` using `tcase_add_checked_fixture`.
 */
void test_session_teardown() {
    free_rtx_frame_entries();
    free_os_frame_entries();
    close_session_subsystem();
}

/* ----------------------------------- Basic Setup Tests ----------------------------------- */

START_TEST(test_session_creation_and_find) {
    session_t* session;
    session_t* created_session;
    session_t* tmp_session;

    // testing that session is not yet created
    session = session_find(SOURCE, address_a, address_b);
    ck_assert_msg(session == NULL, "Session list already contained session which is to be created!");

    // calling session_register on an unregistered session should create one
    created_session = session_register(SOURCE, address_a, address_b);
    ck_assert_msg(created_session != NULL, "Failed session creation!");
    ck_assert_int_eq(created_session->type, SOURCE);
    // TODO do session id compare

    // calling session_register on an registered session should just return that
    tmp_session = session_register(SOURCE, address_a, address_b);
    ck_assert_msg(tmp_session == created_session, "Differing pointers to the same session!");

    // session_find for the inverse flow should not yield a result
    session = session_find(SOURCE, address_b, address_a);
    ck_assert_msg(session == NULL, "After creating session, the other direction was weirdly also present!");

    // session_find for the created session should properly return that!
    session = session_find(SOURCE, address_a, address_b);
    ck_assert_msg(session != NULL, "Failed to find created session!");
    ck_assert_msg(session == created_session, "Pointers to found session differ to the created one!");

    session_free(created_session);
}
END_TEST

/* ----------------------------------- CODING related tests ----------------------------------- */

START_TEST(test_session_coding_simple_two_nodes) {
    session_t* source;
    session_t* destination;

    char* example0 = "Hello World!";
    char* example1 = "Hello World, whats up with you all?";
    char* example2 = "Hello World2!";

    os_frame_entry_t* received;

    source = session_register(SOURCE, address_a, address_b);
    ck_assert_int_eq(source->type, SOURCE);
    destination = session_register(DESTINATION, address_a, address_b);
    ck_assert_int_eq(destination->type, DESTINATION);
    ck_assert_mem_eq(&source->session_id, &destination->session_id, sizeof(session_id));

    session_encoder_add(source, (u8*) example0, strlen(example0));

    forward_frames(destination, 1, true);

    received = peek_os_frame_entry(0);
    ck_assert_int_eq(received->length, strlen(example0));
    ck_assert_str_eq((char*) received->payload, example0);

    session_encoder_add(source, (u8*) example1, strlen(example1));
    session_encoder_add(source, (u8*) example2, strlen(example2));

    forward_frames(destination, 2, true);

    received = peek_os_frame_entry(1);
    ck_assert_int_eq(received->length, strlen(example1));
    ck_assert_str_eq((char*) received->payload, example1);

    received = peek_os_frame_entry(2);
    ck_assert_int_eq(received->length, strlen(example2));
    ck_assert_str_eq((char*) received->payload, example2);
}
END_TEST

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

static int check_rtx_frame(session_t* session, u8* payload, size_t length) {
    rtx_frame_entry_t *entry, *last;
    int index = 0;

    entry = calloc(1, sizeof(rtx_frame_entry_t));
    if (entry == NULL) {
        ck_abort_msg("Failed to alloc a rtx_frame_entry_t");
    }

    if (!list_empty(&rtx_frame_entries)) {
        last = list_last_entry(&rtx_frame_entries, rtx_frame_entry_t, list);
        index = last->index + 1;
    }

    entry->index = index;
    entry->session = session;

    ck_assert_msg(length <= sizeof(entry->payload), "Received frame inside check_rtx_frame() exceeding the length of rtx_frame_entry_t");
    memcpy(entry->payload, payload, length);
    entry->length = length;

    list_add_tail(&entry->list, &rtx_frame_entries);

    return 0;
}

static int check_os_frame(session_t* session, u8* payload, size_t length) {
    os_frame_entry_t *entry, *last;
    int index = 0;

    entry = calloc(1, sizeof(os_frame_entry_t));
    if (entry == NULL) {
        ck_abort_msg("Failed to alloc a os_frame_entry_t");
    }

    if (!list_empty(&os_frame_entries)) {
        last = list_last_entry(&os_frame_entries, os_frame_entry_t, list);
        index = last->index + 1;
    }

    entry->index = index;
    entry->session = session;

    ck_assert_msg(length <= sizeof(entry->payload), "Received frame inside check_os_frame() exceeding the length of os_frame_entry_t");
    memcpy(entry->payload, payload, length);
    entry->length = length;

    list_add_tail(&entry->list, &os_frame_entries);

    return 0;
}

static rtx_frame_entry_t* pop_rtx_frame_entry() {
    rtx_frame_entry_t* entry;

    ck_assert_msg(!list_empty(&rtx_frame_entries), "Tried popping from an emtpy rtx_frame list");

    entry = list_first_entry(&rtx_frame_entries, rtx_frame_entry_t , list);
    ck_assert_msg(entry != NULL, "Failed list_first_entry for rtx_frame list");

    list_del(&entry->list);

    return entry;
}

static os_frame_entry_t * pop_os_frame_entry() {
    os_frame_entry_t* entry;

    ck_assert_msg(!list_empty(&os_frame_entries), "Tried popping from an emtpy os_frame list");

    entry = list_first_entry(&os_frame_entries, os_frame_entry_t , list);
    ck_assert_msg(entry != NULL, "Failed list_first_entry for os_frame list");

    list_del(&entry->list);

    return entry;
}

static rtx_frame_entry_t* peek_rtx_frame_entry(int index) {
    rtx_frame_entry_t* entry;

    list_for_each_entry(entry, &rtx_frame_entries, list) {
        if (entry->index == index) {
            return entry;
        } else if (entry->index > index) {
            break;
        }
    }

    ck_abort_msg("Failed to find frame entry for given index!");
}

static os_frame_entry_t * peek_os_frame_entry(int index) {
    os_frame_entry_t* entry;

    list_for_each_entry(entry, &os_frame_entries, list) {
        if (entry->index == index) {
            return entry;
        } else if (entry->index > index) {
            break;
        }
    }

    ck_abort_msg("Failed to find frame entry for given index!");
}

static void forward_frames(session_t* destination, int count, bool forward_from_source) {
    rtx_frame_entry_t* entry;

    while (count > 0 ) {
        entry = pop_rtx_frame_entry();

        session_decoder_add(destination, entry->payload, entry->length, forward_from_source);
        free(entry);

        count--;
    }
}

static void free_rtx_frame_entries() {
    rtx_frame_entry_t *current, *tmp;

    list_for_each_entry_safe(current, tmp, &rtx_frame_entries, list) {
        list_del(&current->list);
        free(current);
    }
}

static void free_os_frame_entries() {
    os_frame_entry_t *current, *tmp;

    list_for_each_entry_safe(current, tmp, &os_frame_entries, list) {
        list_del(&current->list);
        free(current);
    }
}
