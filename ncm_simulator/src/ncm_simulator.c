//
// Created by Andreas Bauer on 22.02.21.
//

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <moepcommon/util.h>

#include <moepgf/moepgf.h>

#include "moep/types.h"
#include "session.h"
#include "global.h"

session_t* sender_session;
session_t* receiver_session;

#define STRING_ETHER_TYPE 0x0F0F

static bool forward_from_source = false;

int rtx_frame(session_subsystem_context_t* context, session_t* session, coded_packet_metadata_t* metadata, u8* payload, size_t length) {
    (void) context;
    (void) session;

    LOG(LOG_INFO, "Callback to RTX frame from sender to received was called!");
    session_decoder_add(receiver_session, metadata, payload, length, forward_from_source);

    return 0;
}

int os_frame(session_subsystem_context_t* context, session_t* session, u16 ether_type, u8* payload, size_t length) {
    (void) context;
    (void) session;

    assert(STRING_ETHER_TYPE == ether_type);

    LOG(LOG_INFO, "Received a fully decoded frame (type=%#04x):", ether_type);
    for (size_t i = 0; i < length; i++) {
        char* c = ((char*) payload) + i;
        printf("%c", *c);
    }

    printf("\n");

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

int main() {
    session_subsystem_context_t* sender_context;
    session_subsystem_context_t* receiver_context;

    static u8 sender_address[IEEE80211_ALEN] = {0x41, 0x41, 0x41, 0x41, 0x41, 0x41};
    static u8 receiver_address[IEEE80211_ALEN] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42};

    printf("Starting the NCM Simulator...\n");

    sender_context = init_context(sender_address);
    receiver_context = init_context(receiver_address);

    // TODO in order to be able to use the timer framework,
    //  we need to implement a custom signal handler, calling the actual timer callbacks
    //  (or pack in libmoep and use moep_run(..)).

    sender_session = session_register(sender_context, sender_address, receiver_address);
    receiver_session = session_register(receiver_context, sender_address, receiver_address);

    char* test_string = "Hello World!";
    char* test_string2 = "Hello World, whats up with you all?";
    int ret = session_encoder_add(sender_session, STRING_ETHER_TYPE, (u8*) test_string, strlen(test_string));
    assert(ret == 0);

    forward_from_source = true;
    ret = session_encoder_add(sender_session, STRING_ETHER_TYPE, (u8*) test_string2, strlen(test_string2));
    assert(ret == 0);

    session_subsystem_close(sender_context);
    session_subsystem_close(receiver_context);
    return 0;
}
