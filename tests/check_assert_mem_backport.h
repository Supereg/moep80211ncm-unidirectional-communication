//
// Created by Andreas Bauer on 29.03.21.
//

#ifndef CHECK_BACKPORT_H
#define CHECK_BACKPORT_H

#include <check.h>

/*
 * This file contains some macros not available in libcheck 0.10.x.
 * 0.10.x is the latest available for debian,
 * thus we include those header definitions which are only available with
 * libcheck >= 0.11.x to stay compatible.
 */

#ifndef CK_MAX_ASSERT_MEM_PRINT_SIZE
#define CK_MAX_ASSERT_MEM_PRINT_SIZE 64
#endif

#ifndef _ck_assert_mem
#define _ck_assert_mem(X, OP, Y, L) do { \
  const uint8_t* _ck_x = (const uint8_t*)(X); \
  const uint8_t* _ck_y = (const uint8_t*)(Y); \
  size_t _ck_l = (L); \
  char _ck_x_str[CK_MAX_ASSERT_MEM_PRINT_SIZE * 2 + 1]; \
  char _ck_y_str[CK_MAX_ASSERT_MEM_PRINT_SIZE * 2 + 1]; \
  static const char _ck_hexdigits[] = "0123456789abcdef"; \
  size_t _ck_i; \
  size_t _ck_maxl = (_ck_l > CK_MAX_ASSERT_MEM_PRINT_SIZE) ? CK_MAX_ASSERT_MEM_PRINT_SIZE : _ck_l; \
  for (_ck_i = 0; _ck_i < _ck_maxl; _ck_i++) { \
    _ck_x_str[_ck_i * 2  ]   = _ck_hexdigits[(_ck_x[_ck_i] >> 4) & 0xF]; \
    _ck_y_str[_ck_i * 2  ]   = _ck_hexdigits[(_ck_y[_ck_i] >> 4) & 0xF]; \
    _ck_x_str[_ck_i * 2 + 1] = _ck_hexdigits[_ck_x[_ck_i] & 0xF]; \
    _ck_y_str[_ck_i * 2 + 1] = _ck_hexdigits[_ck_y[_ck_i] & 0xF]; \
  } \
  _ck_x_str[_ck_i * 2] = 0; \
  _ck_y_str[_ck_i * 2] = 0; \
  if (_ck_maxl != _ck_l) { \
    _ck_x_str[_ck_i * 2 - 2] = '.'; \
    _ck_y_str[_ck_i * 2 - 2] = '.'; \
    _ck_x_str[_ck_i * 2 - 1] = '.'; \
    _ck_y_str[_ck_i * 2 - 1] = '.'; \
  } \
  ck_assert_msg(0 OP memcmp(_ck_y, _ck_x, _ck_l), \
    "Assertion '%s' failed: %s == \"%s\", %s == \"%s\"", #X" "#OP" "#Y, #X, _ck_x_str, #Y, _ck_y_str); \
} while (0)
#endif

#ifndef ck_assert_mem_eq
#define ck_assert_mem_eq(X, Y, L) _ck_assert_mem(X, ==, Y, L)
#endif

#ifndef ck_assert_mem_ne
#define ck_assert_mem_ne(X, Y, L) _ck_assert_mem(X, !=, Y, L)
#endif

#ifndef ck_assert_mem_lt
#define ck_assert_mem_lt(X, Y, L) _ck_assert_mem(X, <, Y, L)
#endif

#ifndef ck_assert_mem_le
#define ck_assert_mem_le(X, Y, L) _ck_assert_mem(X, <=, Y, L)
#endif

#ifndef ck_assert_mem_gt
#define ck_assert_mem_gt(X, Y, L) _ck_assert_mem(X, >, Y, L)
#endif

#ifndef ck_assert_mem_ge
#define ck_assert_mem_ge(X, Y, L) _ck_assert_mem(X, >=, Y, L)
#endif

#endif //CHECK_BACKPORT_H
