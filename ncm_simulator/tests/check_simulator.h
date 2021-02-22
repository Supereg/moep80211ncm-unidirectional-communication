//
// Created by Andreas Bauer on 22.02.21.
//

#ifndef MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_CHECK_SIMULATOR_H
#define MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_CHECK_SIMULATOR_H

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

#endif //MOEP80211NCM_UNIDIRECTIONAL_COMMUNICATION_CHECK_SIMULATOR_H
