//
// Created by Andreas Bauer on 22.02.21.
//

#include <stdio.h>
#include <string.h>

#include <moepcommon/util.h>

#include <moepgf/moepgf.h>

#include "moep/types.h"
#include "session.h"
#include "global.h"

session_t* sender_session;
session_t* receiver_session;
// TODO intermediate sessions

static bool forward_from_source = false;

/*
void print_stats(rlnc_block_t block, char* name) {
    printf("%s stats: rank_encode: %d, rank_decode: %d, curr_frame_len: %zd\n", name,
           rlnc_block_rank_encode(block), rlnc_block_rank_decode(block), rlnc_block_current_frame_len(block));
    print_block(block);
}
*/

int rtx_frame(session_t* session, u8* payload, size_t length) {
    (void) session;

    LOG(LOG_INFO, "Callback to RTX frame from sender to received was called!");
    session_decoder_add(receiver_session, payload, length, forward_from_source);

    return 0;
}

int os_frame(session_t* session, u8* payload, size_t length) {
    (void) session;

    LOG(LOG_INFO, "Received a fully decoded frame:");
    for (size_t i = 0; i < length; i++) {
        char* c = ((char*) payload) + i;
        printf("%c", *c);
    }

    printf("\n");

    return 0;
}

int main() {
    static u8 sender_address[IEEE80211_ALEN] = {0x41, 0x41, 0x41, 0x41, 0x41, 0x41};
    static u8 receiver_address[IEEE80211_ALEN] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42};

    printf("Starting the NCM Simulator...\n");

    session_subsystem_context* context = init_session_subsystem();
    context->generation_size = GENERATION_SIZE;
    context->generation_window_size = GENERATION_WINDOW_SIZE;
    context->moepgf_type = GF;
    context->rtx_callback = rtx_frame;
    context->os_callback = os_frame;

    // TODO in order to be able to use the timer framework,
    //  we need to implement a custom signal handler, calling the actual timer callbacks
    //  (or pack in libmoep and use moep_run(..)).

    sender_session = session_register(SOURCE, sender_address, receiver_address);
    receiver_session = session_register(DESTINATION, receiver_address, sender_address);

    char* test_string = "Hello World!";
    char* test_string2 = "Hello World, whats up with you all?!";
    session_encoder_add(sender_session, (u8*) test_string, strlen(test_string));

    forward_from_source = true;
    session_encoder_add(sender_session, (u8*) test_string2, strlen(test_string2));

    close_session_subsystem();
    return 0;
}
