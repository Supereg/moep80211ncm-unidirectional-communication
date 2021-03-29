// This file contains all test case definitions related to the `session.c` file.
// The session test `Suite` is created inside `session_suite()`.
//
// To add any tests, use `START_TEST(...)` and `END_TEST` marcos, then modify
// `session_suite()` accordingly, so that `tcase_add_test` is called
// to add the test to a given test case.
//
// Created by Andreas Bauer on 22.02.21.
//

#include "check_session.h"
#include "check_suites.h"

#include "check_utils.h"

#include <stdio.h>
#include <check.h>

#include <moepcommon/util.h>

#include "../src/session.c" // NOLINT(bugprone-suspicious-include)

// packet counter prepended to the buffer of random packets
#define GENERATED_PACKET_NUM_SIZE 4

static u8 address_src[IEEE80211_ALEN] = { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 };
static u8 address_intermediate[IEEE80211_ALEN] = { 0x42, 0x42, 0x42, 0x42, 0x42, 0x42 };
static u8 address_dst[IEEE80211_ALEN] = { 0x43, 0x43, 0x43, 0x43, 0x43, 0x43 };

struct session_subsystem_context* src_context;
struct session_subsystem_context* intermediate_context;
struct session_subsystem_context* dst_context;

/**
 * Configuration for a single execution of a random packet test.
 */
struct random_test_config {
	double forwarding_probability;
	s64 max_forwarding_timeout;
	int packet_gen_min_time;
	int packet_gen_max_time;
};

struct generated_packet {
	struct list_head list;
	size_t length; // the buffer length minus GENERATED_PACKET_NUM_SIZE (prepended)
	u8 buffer[CHECK_MAX_PDU];
};

/**
 * State information for a currently running "random test".
 * Used to pass around information, e.g. to timeouts.
 */
struct random_test_execution {
	session_t* source;
	bool packet_timeout_running;
	const struct random_test_config* config;

	u64 generated_packet_count;

	// list of `generated_packet`s
	struct list_head generated_packets;
};

/* ------------ TEST STUBS simulating any NCM module dependence ------------- */

// neighbour.h
double nb_ul_redundancy_stub_val = 1.0;
double
nb_ul_redundancy(const u8* hwaddr)
{
	(void)hwaddr;
	return nb_ul_redundancy_stub_val;
}

// neighbour.h
double nb_ul_quality_stub_val = 1.0;
double
nb_ul_quality(const u8* hwaddr, int* p, int* q)
{
	(void)hwaddr;
	(void)p;
	(void)q;
	return nb_ul_quality_stub_val;
}

// qdelay.h
int qdelay_packet_cnt_stub_val = 0;
int
qdelay_packet_cnt()
{
	return qdelay_packet_cnt_stub_val;
}

/* -------------------------------------------------------------------------- */

/**
 * Setup is called before **every** test of a `TCase` (Test case).
 * It must be registered to the `TCase` using `tcase_add_checked_fixture`.
 */
void
test_session_setup()
{
	LOG(LOG_INFO, "session_test_setup!");
	init_check_utils();

	src_context = session_subsystem_init(CHECK_GENERATION_SIZE,
		CHECK_GENERATION_WINDOW_SIZE,
		CHECK_GF_TYPE,
		address_src,
		check_rtx_frame_callback,
		check_os_frame_callback,
		NULL,
		0);
	intermediate_context = session_subsystem_init(CHECK_GENERATION_SIZE,
		CHECK_GENERATION_WINDOW_SIZE,
		CHECK_GF_TYPE,
		address_intermediate,
		check_rtx_frame_callback,
		check_os_frame_callback,
		NULL,
		0);
	dst_context = session_subsystem_init(CHECK_GENERATION_SIZE,
		CHECK_GENERATION_WINDOW_SIZE,
		CHECK_GF_TYPE,
		address_dst,
		check_rtx_frame_callback,
		check_os_frame_callback,
		NULL,
		0);
}

/**
 * Teardown is called after **every** test of a `TCase` (Test case).
 * It must be registered to the `TCase` using `tcase_add_checked_fixture`.
 */
void
test_session_teardown()
{
	LOG(LOG_INFO, "session_test_teardown!");
	close_check_utils();

	session_subsystem_close(src_context);
	session_subsystem_close(intermediate_context);
	session_subsystem_close(dst_context);
}

/* --------------------------- Basic Setup Tests ---------------------------- */

/**
 * Test checking basic functionality and handling of a `session_t` struct.
 */
START_TEST(test_session_creation_and_find)
{
	session_t* session;
	session_t* created_src_session;
	session_t* created_dst_session;
	session_t* created_intermediate_session;
	session_t* tmp_session;
	struct session_id expected_id;

	memcpy(expected_id.src_address, address_src, IEEE80211_ALEN);
	memcpy(expected_id.dst_address, address_dst, IEEE80211_ALEN);

	// testing that session is not yet created
	session = session_find(src_context, address_src, address_dst);
	ck_assert_msg(session == NULL,
		"Session list already contained session which is to be created!");

	// calling session_register on an unregistered session should create one
	created_src_session
		= session_register(src_context, address_src, address_dst);
	ck_assert_msg(created_src_session != NULL, "Failed session creation!");
	ck_assert_int_eq(created_src_session->type, SOURCE);
	ck_assert_mem_eq(&created_src_session->session_id,
		&expected_id,
		sizeof(struct session_id));

	// calling session_register on an registered session should just return that
	tmp_session = session_register(src_context, address_src, address_dst);
	ck_assert_msg(tmp_session == created_src_session,
		"Differing pointers to the same session!");

	// session_find for the inverse flow should not yield a result
	session = session_find(src_context, address_dst, address_src);
	ck_assert_msg(session == NULL,
		"After creating session, the other direction was weirdly also present!");

	// session_find for the created session should properly return that!
	session = session_find(src_context, address_src, address_dst);
	ck_assert_msg(session != NULL, "Failed to find created session!");
	ck_assert_msg(session == created_src_session,
		"Pointers to found session differ to the created one!");

	session_free(created_src_session);

	// now test creation of session for destination node
	created_dst_session
		= session_register(dst_context, address_src, address_dst);
	ck_assert_msg(created_dst_session != NULL, "Failed session creation!");
	ck_assert_int_eq(created_dst_session->type,
		DESTINATION); // testing proper session type detection
	ck_assert_mem_eq(&created_dst_session->session_id,
		&expected_id,
		sizeof(struct session_id));

	// now test creation of session for intermediate nodes
	created_intermediate_session = session_register(
		intermediate_context, address_src, address_dst);
	ck_assert_msg(created_intermediate_session != NULL,
		"Failed session creation!");
	ck_assert_int_eq(created_intermediate_session->type,
		INTERMEDIATE); // testing proper session type detection
	ck_assert_mem_eq(&created_intermediate_session->session_id,
		&expected_id,
		sizeof(struct session_id));
}
END_TEST

/* ---------------------------- Statistics Tests ---------------------------- */

/**
 * Test checking the basic functionality of the logging mechanism.
 */
START_TEST(test_session_log)
{
	session_t* created_src_session;
	char* fn;
	FILE* file;
	char* cmp1 = "414141414141434343434343,0,0,0\n";
	char* red1 = NULL;
	size_t len1;
	struct session_id expected_id;

	memcpy(expected_id.src_address, address_src, IEEE80211_ALEN);
	memcpy(expected_id.dst_address, address_dst, IEEE80211_ALEN);

	// calling session_register on an unregistered session should create one
	created_src_session
		= session_register(src_context, address_src, address_dst);
	ck_assert_msg(created_src_session != NULL, "Failed session creation!");
	ck_assert_int_eq(created_src_session->type, SOURCE);
	ck_assert_mem_eq(&created_src_session->session_id,
		&expected_id,
		sizeof(struct session_id));

	fn = session_get_log_filename(created_src_session);
	session_log_state(src_context);
	file = fopen(fn, "r");
	ck_assert_ptr_ne(file, NULL);
	ck_assert_int_gt(getline(&red1, &len1, file), 0);
	ck_assert_str_eq((red1 + 11), cmp1);
	fclose(file);
	free(red1);

	session_free(created_src_session);
}
END_TEST

/* -------------------------- CODING related tests -------------------------- */

/**
 * Test checking coding functionality by sending three example frames
 * over a two node network.
 */
START_TEST(test_session_coding_simple_two_nodes)
{
	check_test_context_t* context;
	session_t* source;
	session_t* destination;

	int ret;

	char* example0 = "Hello World!";
	char* example1 = "Hello World, whats up with you all?";
	char* example2 = "Hello World2!";

	struct os_frame_entry* received;

	// those configurations below are expected to successfully run the unit test
	*(int*)&src_context->generation_size = 2;
	*(int*)&src_context->generation_window_size = 2;
	*(int*)&dst_context->generation_size = 2;
	*(int*)&dst_context->generation_window_size = 2;

	source = session_register(src_context, address_src, address_dst);
	ck_assert_int_eq(source->type, SOURCE);

	destination = session_register(dst_context, address_src, address_dst);
	ck_assert_int_eq(destination->type, DESTINATION);
	ck_assert_mem_eq(&source->session_id,
		&destination->session_id,
		sizeof(struct session_id));

	// defines involved sessions, and forwarding behavior for
	// the rtx callback (check_rtx_frame_callback)
	context = test_init(source, NULL, destination, 1.0, -1);

	ret = session_encoder_add(
		source, CHECK_ETHER_TYPE, (u8*)example0, strlen(example0));
	ck_assert_int_eq(ret, EXIT_SUCCESS);

	await_fully_decoded();

	received = peek_os_frame_entry(0);
	ck_assert_int_eq(received->length, strlen(example0));
	ck_assert_int_eq(received->ether_type, CHECK_ETHER_TYPE);
	ck_assert_str_eq((char*)received->payload, example0);

	ret = session_encoder_add(
		source, CHECK_ETHER_TYPE, (u8*)example1, strlen(example1));
	ck_assert_int_eq(ret, EXIT_SUCCESS);

	await_fully_decoded();

	received = peek_os_frame_entry(1);
	ck_assert_int_eq(received->length, strlen(example1));
	ck_assert_int_eq(received->ether_type, CHECK_ETHER_TYPE);
	ck_assert_str_eq((char*)received->payload, example1);

	// adding the third frame, will test if generation_list_advance works properly
	ret = session_encoder_add(
		source, CHECK_ETHER_TYPE, (u8*)example2, strlen(example2));
	ck_assert_int_eq(ret, EXIT_SUCCESS);

	await_fully_decoded();

	received = peek_os_frame_entry(2);
	ck_assert_int_eq(received->length, strlen(example2));
	ck_assert_int_eq(received->ether_type, CHECK_ETHER_TYPE);
	ck_assert_str_eq((char*)received->payload, example2);

	test_free(context);
}
END_TEST

/**
 * List of configurations the loop test `test_session_coding_random_two_nodes`
 * is called with.
 * This allows to run the same test with different configurations.
 */
const struct random_test_config test_config_coding_random_two_nodes[] = {
	{
		.forwarding_probability = 1,
		.max_forwarding_timeout = 0,
		.packet_gen_min_time = 0,
		.packet_gen_max_time = 2
	},
	{
		.forwarding_probability = 1,
		// using a "high" delay will simulate frames arriving out of order
		.max_forwarding_timeout = 100,
		.packet_gen_min_time = 0,
		.packet_gen_max_time = 2
	},
	{
		.forwarding_probability = 0.9,
		.max_forwarding_timeout = 0,
		.packet_gen_min_time = 2,
		.packet_gen_max_time = 4
	},
	{
		.forwarding_probability = 0.8,
		.max_forwarding_timeout = 0,
		.packet_gen_min_time = 4,
		.packet_gen_max_time = 6
	},
	{
		.forwarding_probability = 0.7,
		.max_forwarding_timeout = 0,
		.packet_gen_min_time = 6,
		.packet_gen_max_time = 8
	},
	{
		.forwarding_probability = 0.5,
		.max_forwarding_timeout = 0,
		.packet_gen_min_time = 8,
		.packet_gen_max_time = 10
	},
};

/**
 * Timeout callback used in the `test_session_coding_random_two_nodes`
 * which is used to generate a single random packet
 * (and adding it to the source node).
 */
static int
random_coding_packet_timeout_callback(timeout_t timeout,
	u32 overrun,
	void* data)
{
	static const char charset[]
		= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	static const int charset_size = sizeof(charset) - 1;

	(void)overrun;
	struct random_test_execution* execution;
	struct generated_packet* packet;

	size_t i;
	u32* packet_counter;
	int next_timeout;
	int ret;

	ck_assert_int_eq(sizeof(*packet_counter), GENERATED_PACKET_NUM_SIZE);

	execution = data;

	if (!execution->packet_timeout_running || !test_initialized()) {
		// test was finished, timeout was cancelled
		return 0;
	}

	if (generation_list_space_remaining(session_generation_list(execution->source)) == 0) {
		// ensure session_encoder_add doesn't drop frames because the timer produced
		// faster than the destination could ACK the frames.
		LOG(LOG_WARNING,
			"packet_timeout ran to fast, generations are full! Skipping...");

		ret = timeout_settime(timeout, 0,
			timeout_msec(execution->config->packet_gen_max_time, 0));
		if (ret != 0) {
			DIE("session test failed to timeout_settime(): %s",
				strerror(errno));
		}
		return 0;
	}

	packet = calloc(1, sizeof(struct generated_packet));
	if (packet == NULL) {
		DIE("random_coding_packet_timeout_callback() failed to calloc generated_packet!");
	}

	// the packet->buffer is prefixed with a GENERATED_PACKET_NUM_SIZE
	// byte long packet counter. This is to test if the packets were
	// received in order and nothing was dropped.
	// packet->length carries the buffer length minus the packet counter length.

	packet->length = random() % (CHECK_MAX_PDU + 1 - GENERATED_PACKET_NUM_SIZE);

	for (i = GENERATED_PACKET_NUM_SIZE; i < packet->length; i++) {
		int key = (int)(random() % (sizeof(charset) - 1));
		packet->buffer[i] = charset[key];
	}

	ck_assert_int_le(execution->generated_packet_count, UINT32_MAX);
	packet_counter = (u32*)packet->buffer;
	*packet_counter = execution->generated_packet_count++;

	list_add_tail(&packet->list, &execution->generated_packets);

	ret = session_encoder_add(execution->source,
		CHECK_ETHER_TYPE,
		packet->buffer,
		packet->length + GENERATED_PACKET_NUM_SIZE);
	if (ret != 0) {
		DIE_SESSION(execution->source,
			"Failed to add random source packet!");
	}

	next_timeout = max(execution->config->packet_gen_min_time,
		(int)(random() % (execution->config->packet_gen_max_time + 1)));

	ret = timeout_settime(timeout, 0, timeout_msec(next_timeout, 0));
	if (ret != 0) {
		DIE("session test failed to timeout_settime(): %s",
			strerror(errno));
	}

	return 0;
}

/**
 * This test considers a network of two nodes (SOURCE and DESTINATION)
 * and sends hundreds to thousands of randomly generated packet
 * through that network.
 * It is a loop test (see `tcase_add_loop_test` and param _i),
 * and run multiple times using different configurations for
 * random packet loss and forwarding times.
 *
 * This tests checks that the implementation properly handles
 * packet loss and e.g. frames arriving out of order.
 *
 * @param _i - The loop index to retrieve the current configuration from.
 * 	The configurations are stored in `test_config_coding_random_two_nodes`.
 */
START_TEST(test_session_coding_random_two_nodes)
{
	static struct random_test_execution execution = { 0 };
	unsigned int seed;
	check_test_context_t* context;
	session_t* source;
	session_t* destination;
	timeout_t packet_timeout;
	int ret;
	struct generated_packet *generated_packet, *tmp;
	u32 expected_packet_num;
	u32 packet_num = 0;
	struct os_frame_entry* os_frame;

	// seed is logged below, in order to reproduce tests
	seed = time(NULL);
	srandom(seed);

	ck_assert_int_eq(
		sizeof(expected_packet_num), GENERATED_PACKET_NUM_SIZE);
	ck_assert_int_eq(sizeof(packet_num), GENERATED_PACKET_NUM_SIZE);

	execution.config = &test_config_coding_random_two_nodes[_i];
	LOG(LOG_INFO,
		"Starting test_session_coding_random_two_nodes with config: seed=%d, prob=%f, timeout=%ld",
		seed,
		execution.config->forwarding_probability,
		execution.config->max_forwarding_timeout);

	// adjust the default configuration for real world tests
	*(int*)&src_context->generation_size = 64;
	*(int*)&src_context->generation_window_size = 4;
	*(int*)&dst_context->generation_size = 64;
	*(int*)&dst_context->generation_window_size = 4;

	// this value is used in the `session_redundancy` function
	// which influences the rtx timeout value
	nb_ul_quality_stub_val = execution.config->forwarding_probability;

	source = session_register(src_context, address_src, address_dst);
	ck_assert_int_eq(source->type, SOURCE);
	destination = session_register(dst_context, address_src, address_dst);
	ck_assert_int_eq(destination->type, DESTINATION);

	context = test_init(source,
		NULL,
		destination,
		execution.config->forwarding_probability,
		execution.config->max_forwarding_timeout);

	execution.source = source;
	execution.packet_timeout_running = true;
	execution.generated_packet_count = 0;
	INIT_LIST_HEAD(&execution.generated_packets);

	// One execution of the timeout corresponds to one generated
	// frame added to the source. The timeout is run irregularly.
	// On every execution a new timeout values is drawn from
	// an interval of e.g. [0;2] (configurable in the random_test_config).
	// The timer runs for 5 seconds.
	// The test with link quality 100% will e.g therefore generate
	// roughly 3k-4k packets depending on the interval drawn.
	// Every packet has a maximum of 1024 byte (whatever set in CHECK_MAX_PDU).
	ret = timeout_create(CLOCK_MONOTONIC,
		&packet_timeout,
		random_coding_packet_timeout_callback,
		&execution);
	if (ret != 0) {
		DIE("session test failed to timeout_create(): %s",
			strerror(errno));
	}

	ret = timeout_settime(packet_timeout, 0, timeout_msec(0, 0));
	if (ret != 0) {
		DIE("session test failed to timeout_settime(): %s",
			strerror(errno));
	}

	// let it run for 5s
	await(5000);

	// cancel and delete packet timeout
	execution.packet_timeout_running = false;
	ret = timeout_clear(packet_timeout);
	if (ret != 0) {
		DIE("session test failed to timeout_clear(): %s",
			strerror(errno));
	}

	// ensure all packets are decoded and acknowledged
	await_fully_decoded();

	ret = timeout_delete(packet_timeout);
	if (ret != 0) {
		DIE("session test failed to timeout_delete(): %s",
			strerror(errno));
	}

	// if nothing was received/sent something is faulty
	ck_assert(!os_frame_entries_emtpy());

	list_for_each_entry_safe (
		generated_packet, tmp, &execution.generated_packets, list) {
		// as explained in random_coding_packet_timeout_callback,
		// first 4 bytes encodes packet num
		expected_packet_num = ((u32*)generated_packet->buffer)[0];
		ck_assert_msg(!os_frame_entries_emtpy(),
			"Expected packet %d but list of decoded packets is empty.",
			expected_packet_num);
		os_frame = pop_os_frame_entry();

		// ensure no packets are dropped or delivered out of order.
		ck_assert_int_eq(expected_packet_num, packet_num);

		ck_assert_int_eq(os_frame->ether_type, CHECK_ETHER_TYPE);
		ck_assert_int_eq(os_frame->length,
			generated_packet->length + GENERATED_PACKET_NUM_SIZE);
		ck_assert_mem_eq(os_frame->payload,
			generated_packet->buffer,
			os_frame->length);

		list_del(&generated_packet->list);
		free(generated_packet);
		free(os_frame);

		packet_num++;
	}

	ck_assert(os_frame_entries_emtpy());

	test_free(context);
}
END_TEST

/* -------------------------------------------------------------------------- */

Suite*
session_suite()
{
	Suite* suite;

	TCase* session_handling;
	TCase* session_coding;
	TCase* session_random_coding;
	TCase* session_logging;

	suite = suite_create("session");

	session_handling = tcase_create("Session Creation & Find");
	session_coding = tcase_create("Session Coding");
	session_random_coding = tcase_create("Session Random Coding");
	session_logging = tcase_create("Session Logging");

	tcase_add_checked_fixture(
		session_handling, test_session_setup, test_session_teardown);
	tcase_add_test(session_handling, test_session_creation_and_find);

	tcase_add_checked_fixture(
		session_coding, test_session_setup, test_session_teardown);
	tcase_add_test(session_coding, test_session_coding_simple_two_nodes);

	tcase_add_checked_fixture(session_random_coding,
		test_session_setup,
		test_session_teardown);

	size_t random_coding_test_count
		= sizeof(test_config_coding_random_two_nodes)
		  / sizeof(struct random_test_config);
	tcase_add_loop_test(session_random_coding,
		test_session_coding_random_two_nodes,
		0, random_coding_test_count);
	// every test runs for at least 5 seconds
	tcase_set_timeout(session_random_coding,20);

	tcase_add_checked_fixture(
		session_logging, test_session_setup, test_session_teardown);
	tcase_add_test(session_coding, test_session_log);

	suite_add_tcase(suite, session_handling);
	suite_add_tcase(suite, session_coding);
	suite_add_tcase(suite, session_random_coding);
	suite_add_tcase(suite, session_logging);

	return suite;
}

/* ------- Internal session.c functionality exposed to unit test API -------- */

struct list_head*
session_generation_list(session_t* session)
{
	return &session->generations_list;
}
