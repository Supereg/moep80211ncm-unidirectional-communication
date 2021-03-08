//
// Created by Andreas Bauer on 22.02.21.
//

#ifndef MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_CHECK_SIMULATOR_H
#define MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_CHECK_SIMULATOR_H

#include <check.h>

/**
 * The Check `Suite` packaging everything related to the `generation.c` module.
 * Refer to the `check_generation.c` file for the individual test case definitions.
 *
 * @return The test `Suite` for the check framework, containing all test cases related to generation.
 */
Suite* generation_suite(void);

/**
 * The Check `Suite` packaging everything related to the `session.c` module.
 * Refer to the `check_session.c` file for the individual test case definitions.
 *
 * @return The test `Suite` for the check framework, containing all test cases related to session.
 */
Suite* session_suite(void);

// some test might expect those specific values, so be aware when changing them!
#define CHECK_GF_TYPE MOEPGF16
#define CHECK_GENERATION_SIZE 4
#define CHECK_GENERATION_WINDOW_SIZE 1 // TODO to be adjusted
#define CHECK_MAX_PDU 1024
#define CHECK_ALIGNMENT 32

#endif //MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_CHECK_SIMULATOR_H
