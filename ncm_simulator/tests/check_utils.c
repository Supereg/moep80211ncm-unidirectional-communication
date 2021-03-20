// This file contains any utils needed for our unit test cases.
// As the session.c and generation.c feature some dynamic behavior,
// like callbacks and timers, we need to utility code
// to deal with those in linearly executing unit tests.
//
// Created by Andreas Bauer on 19.03.21.
//

#include "check_utils.h"

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

#define POP_BLOCKING_ENTRY(list_head, entry, type, name) \
do { \
    await_list_entries(list_head); \
    ck_assert_msg(!list_empty(list_head), "Tried popping from emtpy "name" list even though we waited!"); \
    (entry) = list_first_entry(list_head, type , list); \
    ck_assert_msg((entry) != NULL, "Failed list_first_entry for "name" list"); \
    list_del(&(entry)->list); \
} while(0) \

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
    frame_entry_t *current, *tmp; \
    list_for_each_entry_safe(current, tmp, list_head, list) { \
        list_del(&current->list); \
        free(current); \
    } \
} while (0)


#define POLLING_FINISHED (-2)
#define TIMEOUT_SIG SIGRTMIN
#define AWAIT_MAX_TRIES 100
#define AWAIT_TIME 2


struct util_context {
    bool initialized;

    int epoll_fd;
    struct epoll_event event;

    sigset_t old_set;
    int signal_fd;
};

static struct util_context util_context = {0};

static LIST_HEAD(rtx_frame_entries);
static LIST_HEAD(ack_frame_entries);
static LIST_HEAD(os_frame_entries);


void forward_rtx_frames(session_t* destination, int count, bool call_os_callback) {
    int ret;
    frame_entry_t* entry;

    while (count > 0 ) {
        entry = pop_blocking_rtx_frame_entry();

        ret = session_decoder_add(destination, &entry->metadata, entry->payload, entry->length, call_os_callback);
        ck_assert_int_eq(ret, EXIT_SUCCESS);
        free(entry);

        count--;
    }
}

void forward_ack_frames(session_t* destination, int count) {
    int ret;
    frame_entry_t* entry;

    while (count > 0 ) {
        entry = pop_blocking_ack_frame_entry();

        ret = session_decoder_add(destination, &entry->metadata, entry->payload, entry->length, false);
        ck_assert_int_eq(ret, EXIT_SUCCESS);
        free(entry);

        count--;
    }
}

// -------------- below is all logic related to timeout execution -------------

void init_check_utils() {
    sigset_t timer_sig_set;

    memset(&util_context, 0, sizeof(struct util_context));

    util_context.epoll_fd = epoll_create1(0);
    if (util_context.epoll_fd < 0) {
        ck_abort_msg("Failed to epoll_create1() with error: %s", strerror(errno));
    }

    sigemptyset(&util_context.old_set);
    sigemptyset(&timer_sig_set);
    sigaddset(&timer_sig_set, TIMEOUT_SIG);
    sigprocmask(SIG_BLOCK, &timer_sig_set, &util_context.old_set);

    util_context.signal_fd = signalfd(-1, &timer_sig_set, SFD_NONBLOCK);
    if (util_context.signal_fd < 0) {
        ck_abort_msg("Failed to signalfd() with error: %s", strerror(errno));
    }

    util_context.event.events = EPOLLIN;
    util_context.event.data.ptr = NULL;
    int ret = epoll_ctl(util_context.epoll_fd, EPOLL_CTL_ADD, util_context.signal_fd, &util_context.event);
    if (ret != 0) {
        ck_abort_msg("Failed to epoll_ctl() with error: %s", strerror(errno));
    }

    util_context.initialized = true;
}

void close_check_utils() {
    close(util_context.signal_fd);
    sigprocmask(SIG_SETMASK, &util_context.old_set, NULL);
    close(util_context.epoll_fd);

    memset(&util_context, 0, sizeof(struct util_context));
}

static int exec_queued_timers(struct util_context context) {
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

    ck_assert_msg(siginfo.ssi_signo == (uint32_t) TIMEOUT_SIG, "Unexpected signal number: %d (%d)", siginfo.ssi_signo, TIMEOUT_SIG);
    ck_assert_msg(siginfo.ssi_code == SI_TIMER, "Unexpected signal code: %d (%d)", siginfo.ssi_code, TIMEOUT_SIG);

    return timeout_exec((void*) siginfo.ssi_ptr, siginfo.ssi_overrun);
}

static void check_run_loop() {
    struct epoll_event event;
    int count;
    int ret = 0;

    ck_assert_msg(util_context.initialized == true, "init_check_utils() must be called before you can await list entries!");

    do {
        count = epoll_wait(util_context.epoll_fd, &event, 1, -1);
        if (count < 0) {
            ck_abort_msg("Failed to epoll_wait() with error: %s", strerror(errno));
        } else if (count == 0) {
            continue;
        } else if (count > 1) {
            ck_abort_msg("Failed epoll_wait() received more than one event!");
        }

        ret = exec_queued_timers(util_context);

        if (ret == POLLING_FINISHED) {
            break;
        } else if (ret != 0) {
            LOG(LOG_ERR, "timeout_exec() failed: %d", ret);
        }

    } while(ret == 0 || errno == EINTR);
}

static int await_callback(timeout_t timeout, u32 overrun, void* data) {
    (void) timeout;
    (void) overrun;
    (void) data;
    return POLLING_FINISHED;
}

static void await_list_entries(struct list_head* list_head) {
    timeout_t timeout;
    int ret;
    int executions = 0;

    if (!list_empty(list_head)) {
        return; // nothing do init
    }

    ret = timeout_create(CLOCK_MONOTONIC, &timeout, await_callback, NULL);
    if (ret != 0) {
        DIE("await_list_entries() failed timeout_create(): %s", strerror(errno));
    }

    do {
        ret = timeout_settime(timeout, 0, timeout_msec(AWAIT_TIME, 0));
        if (ret != 0) {
            timeout_delete(timeout);
            DIE("await_list_entries() [exec=%d] failed to timeout_settime(): %s", executions, strerror(errno));
        }

        check_run_loop();
        executions++;

        if (!list_empty(list_head)) {
            break;
        }
    } while (executions <= AWAIT_MAX_TRIES);

    timeout_delete(timeout);

    if (list_empty(list_head)) {
        ck_abort_msg("List still empty though we waited %dx%dms", AWAIT_MAX_TRIES, AWAIT_TIME);
    }
}

// ----------------- below are all "simple list operations" -------------------

frame_entry_t* pop_rtx_frame_entry() {
    frame_entry_t* entry;
    POP_ENTRY(&rtx_frame_entries, entry, frame_entry_t, "rtx_frame");
    return entry;
}

frame_entry_t* pop_blocking_rtx_frame_entry() {
    frame_entry_t* entry;
    POP_BLOCKING_ENTRY(&rtx_frame_entries, entry, frame_entry_t, "rtx_frame");
    return entry;
}

frame_entry_t* peek_rtx_frame_entry(int index) {
    frame_entry_t* entry;
    PEEK_ENTRY(&rtx_frame_entries, entry, index, "rtx_frame");
    return entry;
}


frame_entry_t* pop_ack_frame_entry() {
    frame_entry_t* entry;
    POP_ENTRY(&ack_frame_entries, entry, frame_entry_t, "ack_frame");
    return entry;
}

frame_entry_t* pop_blocking_ack_frame_entry() {
    frame_entry_t* entry;
    POP_BLOCKING_ENTRY(&ack_frame_entries, entry, frame_entry_t, "ack_frame");
    return entry;
}

frame_entry_t* peek_ack_frame_entry(int index) {
    frame_entry_t* entry;
    PEEK_ENTRY(&ack_frame_entries, entry, index, "ack_frame");
    return entry;
}


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


void check_utils_lists_free() {
    FREE_LIST(&rtx_frame_entries);
    FREE_LIST(&ack_frame_entries);
    FREE_LIST(&os_frame_entries);
}

// ------- below are the session context callbacks which must be hooked -------

int check_rtx_frame_callback(session_subsystem_context_t* context, session_t* session, coded_packet_metadata_t* metadata, u8* payload, size_t length) {
    (void) context;

    frame_entry_t *entry, *last;
    int index = 0;

    entry = calloc(1, sizeof(frame_entry_t));
    if (entry == NULL) {
        ck_abort_msg("Failed to alloc a frame_entry_t");
    }

    if (!list_empty(&rtx_frame_entries)) {
        last = list_last_entry(&rtx_frame_entries, frame_entry_t, list);
        index = last->index + 1;
    }

    entry->index = index;
    entry->session = session;

    memcpy(&entry->metadata, metadata, sizeof(coded_packet_metadata_t));

    ck_assert_msg(length <= sizeof(entry->payload), "Received frame inside check_rtx_frame_callback() exceeding the length of frame_entry_t");
    memcpy(entry->payload, payload, length);
    entry->length = length;

    if (metadata->ack) {
        list_add_tail(&entry->list, &ack_frame_entries);
    } else {
        list_add_tail(&entry->list, &rtx_frame_entries);
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

    return 0;
}
