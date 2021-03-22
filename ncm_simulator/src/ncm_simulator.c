//
// Created by Andreas Bauer on 22.02.21.
//

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <argp.h>
#include <sys/signalfd.h>

#include <moepcommon/util.h>

#include <moepgf/moepgf.h>

#include <moep/system.h>
#include <moepcommon/timeout.h>
#include "moep/types.h"
#include "session.h"
#include "global.h"

#define STRING_ETHER_TYPE 0x0F0F

struct arguments arguments;

session_t* sender_session;
session_t* receiver_session;

/* --------------------------------- ARG Parsing --------------------------------- */

const char* argp_program_version = "ncm_simulator 1.0";
const char* argp_program_bug_address = "Andreas Bauer <andi.bauer@tum.de>, Lion Steger <stegerl@in.tum.de>";

static char doc[] =
    "ncm_simulator - the moep80211 network coding simulator. \n"
    "It is used to run the unidirectional sessions subsystem without requiring the network stack.\n"
    "The simulator creates each one SOURCE, INTERMEDIATE, DESTINATION node and whatever is put into stdin, is sent through the 'network'.\n";

// see https://www.linuxtopia.org/online_books/programming_books/gnu_libc_guide/Argp-Option-Flags.html for flags
static struct argp_option options[] = {
    {
        .name   = "ci-mode",
        .key    = 'c',
        .arg    = NULL,
        .flags  = 0,
        .doc    = "Run the simulator in CI mode. Runs a predefined example, thus doesn't read from stdin.",
    },
    {NULL}
};

struct arguments {
    bool ci_mode;
};

static void argument_defaults(struct arguments* arguments) {
    arguments->ci_mode = 0;
}

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    struct arguments* arguments = state->input;

    if (key == 'c') {
        arguments->ci_mode = true;
    } else {
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = {
    .options = options,
    .parser	= parse_opt,
    .args_doc = NULL,
    .doc = doc,
};

/* ------------------------------------------------------------------------------- */

int rtx_frame(session_subsystem_context_t* context, session_t* session, coded_packet_metadata_t* metadata, u8* payload, size_t length) {
    (void) context;
    (void) session;

    if (session == receiver_session) {
        LOG(LOG_INFO, "Callback to ACK frame from receiver to sender was called!");
        session_decoder_add(sender_session, metadata, payload, length);
    } else if (session == sender_session) {
        LOG(LOG_INFO, "Callback to RTX frame from sender to receiver was called!");
        session_decoder_add(receiver_session, metadata, payload, length);
    } else {
        DIE_SESSION(session, "Unknown session!");
    }

    return 0;
}

int os_frame(session_subsystem_context_t* context, session_t* session, u16 ether_type, u8* payload, size_t length) {
    (void) context;
    (void) session;
    char message[MAX_PDU_SIZE + 1] = {0};

    assert(STRING_ETHER_TYPE == ether_type);
    memcpy(message, payload, length);

    printf("Received a fully decoded frame (type=%#04x): %s", ether_type, message);

    return 0;
}

session_subsystem_context_t* init_context(u8* address) {
    return session_subsystem_init(
        GENERATION_SIZE,
        GENERATION_WINDOW_SIZE,
        GF,
        address,
        rtx_frame,
        os_frame);
}

int signal_handler(struct signalfd_siginfo* signal_info, void* data) { // copied from ncm module
    (void) data;

    if (signal_info->ssi_signo == SIGINT || signal_info->ssi_signo == SIGTERM) {
        errno = 0;
        return -1;
    } else if (signal_info->ssi_signo == (uint32_t) SIGRTMIN && signal_info->ssi_code == SI_TIMER) {
        if (timeout_exec((void *)signal_info->ssi_ptr, signal_info->ssi_overrun) != 0) {
            LOG(LOG_ERR, "timeout_exec() failed");
        }
    } else {
        LOG(LOG_WARNING, "signal_handler(): unknown signal %d", signal_info->ssi_signo);
    }

    return 0;
}

int stdin_callback_handler(int fd, u32 events, void* data) {
    (void) events;
    (void) data;

    static char buffer[MAX_PDU_SIZE + 1];

    assert(fd == fileno(stdin));

    memset(buffer, 0, sizeof(buffer));

    // read includes the linebreak.
    ssize_t length = read(fileno(stdin), buffer, sizeof(buffer) - 1);

    int ret = session_encoder_add(sender_session, STRING_ETHER_TYPE, (u8*) buffer, length);
    assert(ret == 0);
    return 0;
}

void run_ci_example() {
    char* test_string = "Hello World!";
    char* test_string2 = "Hello World, whats up with you all?";
    int ret = session_encoder_add(sender_session, STRING_ETHER_TYPE, (u8*) test_string, strlen(test_string));
    assert(ret == 0);

    ret = session_encoder_add(sender_session, STRING_ETHER_TYPE, (u8*) test_string2, strlen(test_string2));
    assert(ret == 0);
}

int main(int argc, char *argv[]) {
    static u8 sender_address[IEEE80211_ALEN] = {0x41, 0x41, 0x41, 0x41, 0x41, 0x41};
    static u8 receiver_address[IEEE80211_ALEN] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42};

    moep_callback_t callback;

    session_subsystem_context_t* sender_context;
    session_subsystem_context_t* receiver_context;

    argument_defaults(&arguments);
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    LOG(LOG_INFO, "Starting the NCM Simulator...\n");

    sender_context = init_context(sender_address);
    receiver_context = init_context(receiver_address);

    sender_session = session_register(sender_context, sender_address, receiver_address);
    receiver_session = session_register(receiver_context, sender_address, receiver_address);

    if (arguments.ci_mode) {
        LOG(LOG_ERR, "CI mode is disabled for now!");
        // TODO run_ci_example(); (deactivated for now, as it would need to be adjusted due to timeout support)
    } else {
        // creates the stdin callback using epoll event EPOLLIN (called whenever a new line is available from stdin)
        callback = moep_callback_create(fileno(stdin), stdin_callback_handler, NULL, EPOLLIN);
        if (callback == NULL) {
            LOG(LOG_ERR, "Failed to created stdin moep callback!");
            return -1;
        }

        moep_run(signal_handler, NULL);

        moep_callback_delete(callback);
    }


    session_subsystem_close(sender_context);
    session_subsystem_close(receiver_context);
    return 0;
}
