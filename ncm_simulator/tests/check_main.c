//
// Created by Andreas Bauer on 22.02.21.
//

#include <stdlib.h>
#include <check.h>

#include "check_simulator.h"

int main()
{
    int number_failed;
    SRunner* runner;
    Suite* g_suite;
    Suite* s_suite;

    // Create all test suites.
    g_suite = generation_suite();
    s_suite = session_suite();

    // Create the runner and add all above created suites.
    runner = srunner_create(g_suite);
    srunner_add_suite(runner, s_suite);

    // Execute the runner.
    srunner_run_all(runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);

    return number_failed == 0? EXIT_SUCCESS: EXIT_FAILURE;
}
