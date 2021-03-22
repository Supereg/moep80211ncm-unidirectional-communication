// This file contains any utils needed for our unit test cases.
// As the session.c and generation.c feature some dynamic behavior,
// like callbacks and timers, we need to utility code
// to deal with those in linearly executing unit tests.
//
// Created by Andreas Bauer on 19.03.21.
//

#include "check_utils.h"

#include <assert.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>

#include <moepcommon/list.h>
#include <moepcommon/timeout.h>
#include <moepcommon/util.h>

#define POP_ENTRY(list_head, entry, type, name) \
do { \
    ck_assert_msg(!list_empty(list_head), "Tried popping from emtpy "name" list"); \
    (entry) = list_first_entry(list_head, type , list); \
    ck_assert_msg((entry) != NULL, "Failed list_first_entry for "name" list"); \
    list_del(&(entry)->list); \
} while (0)

#define PEEK_ENTRY(list_head, entry, peek_index, name) \
do { \
    bool found = false; \
    list_for_each_entry(entry, list_head, list) { \
        if ((entry)->index == (peek_index)) { \
            found = true; \
            break; \
        } else if ((entry)->index > (peek_index)) { \
            break; \
        } \
    } \
    if (!found) { \
        ck_abort_msg("Failed to find "name" entry for given index!"); \
    } \
} while (0)

#define FREE_LIST(list_head) \
do { \
    os_frame_entry_t *current, *tmp; \
    list_for_each_entry_safe(current, tmp, list_head, list) { \
        list_del(&current->list); \
        free(current); \
    } \
} while (0)


#define CHECK_TIMEOUT_SIG SIGRTMIN
#define AWAIT_FINISHED (-1003)
#define AWAIT_TIMEOUT (-1004)

/**
 * State data for a specific test currently in execution.
 */
struct check_test_context {
    session_t* source;
    session_t* intermediate; // NULL if running without forwarders
    session_t* destination;

    double forwarding_probability; // [0;1]
    int forwarding_timeout; // -1 for no timeout
};

struct check_context {
    bool initialized;

    int epoll_fd;
    struct epoll_event event;

    sigset_t old_set;
    int signal_fd;

    struct check_test_context* current_test;
};

static LIST_HEAD(os_frame_entries);
static bool os_frame_await_running = false;
static timeout_t os_frame_await_timeout = NULL;

static struct check_context check_context = {0};

check_test_context_t* test_init(
    session_t* source,
    session_t* intermediate,
    session_t* destination,
    double forwarding_probability,
    int forwarding_timeout) {
    struct check_test_context* context;

    context = calloc(1, sizeof(struct check_test_context));
    if (context == NULL) {
        DIE("init_test() failed to calloc check_test_context!");
    }

    assert(source != NULL);
    assert(forwarding_probability >= 0 && forwarding_probability <= 1);

    context->source = source;
    context->intermediate = intermediate;
    context->destination = destination;
    context->forwarding_probability = forwarding_probability;
    context->forwarding_timeout = forwarding_timeout;

    check_context.current_test = context;

    return context;
}

void test_free(check_test_context_t* context) {
    assert(check_context.current_test == context);
    check_context.current_test = NULL;

    free(context);
}

// -------------- below is all logic related to timeout execution -------------

void init_check_utils() {
    sigset_t timer_sig_set;

    memset(&check_context, 0, sizeof(struct check_context));

    check_context.epoll_fd = epoll_create1(0);
    if (check_context.epoll_fd < 0) {
        ck_abort_msg("Failed to epoll_create1() with error: %s", strerror(errno));
    }

    sigemptyset(&check_context.old_set);
    sigemptyset(&timer_sig_set);
    sigaddset(&timer_sig_set, CHECK_TIMEOUT_SIG);
    sigprocmask(SIG_BLOCK, &timer_sig_set, &check_context.old_set);

    check_context.signal_fd = signalfd(-1, &timer_sig_set, SFD_NONBLOCK);
    if (check_context.signal_fd < 0) {
        ck_abort_msg("Failed to signalfd() with error: %s", strerror(errno));
    }

    check_context.event.events = EPOLLIN;
    check_context.event.data.ptr = NULL;
    int ret = epoll_ctl(check_context.epoll_fd, EPOLL_CTL_ADD, check_context.signal_fd, &check_context.event);
    if (ret != 0) {
        ck_abort_msg("Failed to epoll_ctl() with error: %s", strerror(errno));
    }

    check_context.initialized = true;
}

void close_check_utils() {
    // ensure there aren't any more signals queued, otherwise test runner will crash.
    await(10);

    close(check_context.signal_fd);
    sigprocmask(SIG_SETMASK, &check_context.old_set, NULL);
    close(check_context.epoll_fd);

    memset(&check_context, 0, sizeof(struct check_context));

    FREE_LIST(&os_frame_entries);
}

static int exec_queued_timers(struct check_context context) {
    struct signalfd_siginfo siginfo;
    ssize_t length;

    do {
        length = read(context.signal_fd, &siginfo, sizeof(struct signalfd_siginfo));
    } while (length < 0 && errno == EINTR);

    if (length < 0) {
        if (errno == EAGAIN) { // non-blocking fd, nothing new available
            return 0;
        }
        return -1;
    }

    ck_assert_msg(siginfo.ssi_signo == (uint32_t) CHECK_TIMEOUT_SIG, "Unexpected signal number: %d (%d)", siginfo.ssi_signo, CHECK_TIMEOUT_SIG);
    ck_assert_msg(siginfo.ssi_code == SI_TIMER, "Unexpected signal code: %d (%d)", siginfo.ssi_code, CHECK_TIMEOUT_SIG);

    return timeout_exec((void*) siginfo.ssi_ptr, siginfo.ssi_overrun);
}

static void run_loop() {
    struct epoll_event event;
    int count;
    int ret = 0;

    ck_assert_msg(check_context.initialized == true, "init_check_utils() must be called before you can await list entries!");

    do {
        count = epoll_wait(check_context.epoll_fd, &event, 1, -1);
        if (count < 0) {
            ck_abort_msg("Failed to epoll_wait() with error: %s", strerror(errno));
        } else if (count == 0) {
            continue;
        } else if (count > 1) {
            ck_abort_msg("Failed epoll_wait() received more than one event!");
        }

        ret = exec_queued_timers(check_context);

        if (ret == AWAIT_FINISHED) {
            break;
        } else if (ret != 0) {
            LOG(LOG_ERR, "timeout_exec() failed: %d", ret);
        }

    } while(ret == 0 || errno == EINTR);
}

static int await_finish_callback(timeout_t timeout, u32 overrun, void* data) {
    (void) timeout;
    (void) overrun;
    (void) data;
    return AWAIT_FINISHED;
}

static int await_timeout_callback(timeout_t timeout, u32 overrun, void* data) {
    (void) timeout;
    (void) overrun;
    (void) data;
    return AWAIT_TIMEOUT;
}

static void do_await(timeout_cb_t callback, s64 timeout_ms) {
    timeout_t timeout;
    int ret;

    ret = timeout_create(CLOCK_MONOTONIC, &timeout, callback, NULL);
    if (ret != 0) {
        DIE("await() failed timeout_create(): %s", strerror(errno));
    }

    ret = timeout_settime(timeout, 0, timeout_msec(timeout_ms, 0));
    if (ret != 0) {
        timeout_delete(timeout);
        DIE("await() failed to timeout_settime(): %s", strerror(errno));
    }

    run_loop();

    timeout_delete(timeout);
}

void await(int ms) {
    do_await(await_finish_callback, ms);
}

void await_os_frame() {
    // make check_os_frame_callback() call schedule_os_await_timeout() to gracefully exit the run loop
    os_frame_await_running = true;
    do_await(await_timeout_callback, 20000);
    os_frame_await_running = false;

    if (os_frame_await_timeout != NULL) {
        timeout_delete(os_frame_await_timeout);
        os_frame_await_timeout = NULL;
    }
}

static void create_os_await_timeout() {
    int ret;

    ret = timeout_create(CLOCK_MONOTONIC, &os_frame_await_timeout, await_finish_callback, NULL);
    if (ret != 0) {
        DIE("schedule_os_await_timeout() failed timeout_create(): %s", strerror(errno));
    }
}

static void schedule_os_await_timeout() {
    int ret;

    ret = timeout_settime(os_frame_await_timeout, 0, timeout_msec(1, 0));
    if (ret != 0) {
        timeout_delete(os_frame_await_timeout);
        DIE("schedule_os_await_timeout() failed to timeout_settime(): %s", strerror(errno));
    }
}

// ----------------- below are all "simple list operations" -------------------

os_frame_entry_t* pop_os_frame_entry() {
    os_frame_entry_t* entry;
    POP_ENTRY(&os_frame_entries, entry, os_frame_entry_t, "os_frame");
    return entry;
}

os_frame_entry_t* peek_os_frame_entry(int index) {
    os_frame_entry_t* entry;
    PEEK_ENTRY(&os_frame_entries, entry, index, "os_frame");
    return entry;
}

// ------- below are the session context callbacks which must be hooked -------

struct stored_rtx_frame {
    session_t* session;
    coded_packet_metadata_t metadata;
    u8 payload[CHECK_MAX_PDU];
    size_t length;
};

static void exec_session_decoder_add(struct stored_rtx_frame* frame) {
    int ret;

    assert(check_context.current_test != NULL && "Current test isn't available anymore!");

    ret = session_decoder_add(frame->session, &frame->metadata, frame->payload, frame->length);
    ck_assert_int_eq(ret, 0);

    if (frame->session == check_context.current_test->source) {
        // TODO we assume the ACK is what we want in state (this will not work with multiple session_encoded_added())
        if (os_frame_await_timeout != NULL && !timeout_active(os_frame_await_timeout)) {
            schedule_os_await_timeout();
        }
    }
    free(frame);
}

int check_rtx_frame_callback(session_subsystem_context_t* session_context, session_t* session, coded_packet_metadata_t* metadata, u8* payload, size_t length) {
    (void) session_context;
    check_test_context_t* test_context;
    struct stored_rtx_frame* frame;

    test_context = check_context.current_test;
    assert(test_context != NULL && "Test wasn't properly initialized!");

    frame = calloc(1, sizeof(struct stored_rtx_frame));
    if (frame == NULL) {
        ck_abort_msg("Failed to calloc stored_rtx_frame");
    }

    memcpy(&frame->metadata, metadata, sizeof(coded_packet_metadata_t));

    ck_assert_msg(length <= sizeof(frame->payload), "Received frame inside check_rtx_frame_callback() exceed the length of stored_rtx_frame");
    memcpy(frame->payload, payload, length);
    frame->length = length;

    if (session == test_context->source) {
        assert(test_context->intermediate == NULL);
        frame->session = test_context->destination;
    } else if (session == test_context->intermediate) {
        DIE_SESSION(session, "Intermediate nodes are currently not supported!");
    } else if (session == test_context->destination) {
        assert(test_context->intermediate == NULL);
        frame->session = test_context->source;
    } else {
        DIE_SESSION(session, "Unknown session!");
    }

    long int rnd_boundary = (long int) (test_context->forwarding_probability * RAND_MAX);

    if (random() > rnd_boundary) {
        LOG_SESSION(LOG_INFO, session, "Packet dropped: gen_seq=%d ack=%d", metadata->generation_sequence, metadata->ack);
    } else {
        if (test_context->forwarding_timeout < 0) {
            exec_session_decoder_add(frame);
        } else {
            DIE_SESSION(session, "Forwarding timeouts are unsupported!");
        }
    }

    return 0;
}

int check_os_frame_callback(session_subsystem_context_t* context, session_t* session, u16 ether_type, u8* payload, size_t length) {
    (void) context;

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

    entry->ether_type = ether_type;

    ck_assert_msg(length <= sizeof(entry->payload), "Received frame inside check_os_frame_callback() exceeding the length of os_frame_entry_t");
    memcpy(entry->payload, payload, length);
    entry->length = length;

    list_add_tail(&entry->list, &os_frame_entries);

    if (os_frame_await_running) {
        create_os_await_timeout();
    }

    return 0;
}
