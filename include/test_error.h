/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the HTTP course project developed for
 * the Computer Networks course (15-441/641) taught at Carnegie
 * Mellon University.
 *
 * No part of the HTTP project may be copied and/or distributed
 * without the express permission of the 15-441/641 course staff.
 */
#ifndef TEST_ERROR_H
#define TEST_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

// Internal error codes
typedef enum test_error_code_t {
    // OK (DO NOT TOUCH)
    TEST_ERROR_NONE = 0,
    /* HTTP CONN Errors */
    TEST_ERROR_HTTP_CONNECT_FAILED,
    TEST_ERROR_HTTP_SEND_FAILED,

    /* HTTP PARSE Errors */
    TEST_ERROR_PARSE_PARTIAL,
    TEST_ERROR_PARSE_FAILED,
}
test_error_code_t;

#ifdef __cplusplus
}
#endif

#endif // HARNESS_ERROR_H