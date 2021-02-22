// This file contains all test case definitions related to the `generation.c` file.
// The generation test `Suite` is created inside `generation_suite()`.
//
// To add any tests, use `START_TEST(...)` and `END_TEST` marcos,
// then modify `generation_suite()` accordingly, so that `tcase_add_test` is called
// to add the test to a given test case.
//
// Created by Andreas Bauer on 22.02.21.
//

#include <stdio.h>
#include <check.h>

#include "../src/generation.h"

/**
 * Setup is called before **every** test of a `TCase` (Test case).
 * It must be registered to the `TCase` using `tcase_add_checked_fixture`.
 */
void test_generation_setup() {

}

/**
 * Teardown is called after **every** test of a `TCase` (Test case).
 * It must be registered to the `TCase` using `tcase_add_checked_fixture`.
 */
void test_generation_teardown() {

}

START_TEST(test_generation_hello_world)
{
    int result = generation_hello_world();
    ck_assert_int_eq(result, 3);
}
END_TEST

Suite* generation_suite() {
    Suite *suite;
    TCase *hello_world_case;

    suite = suite_create("generation");

    hello_world_case = tcase_create("Hello World");

    tcase_add_checked_fixture(hello_world_case, test_generation_setup, test_generation_teardown);
    tcase_add_test(hello_world_case, test_generation_hello_world);
    suite_add_tcase(suite, hello_world_case);

    return suite;
}
