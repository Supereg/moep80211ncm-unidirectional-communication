//
// Created by Andreas Bauer on 22.02.21.
//

#include <stdio.h>

#include "../../src/global.h"
#include "generation.h"
#include "session.h"

int main() {
    printf("Hello World! What's up?\n");
    printf("Default MTU %d\n", DEFAULT_MTU);

    printf("generation: %d\n", generation_hello_world());
    printf("session: %d\n", session_hello_world());
    return 0;
}
