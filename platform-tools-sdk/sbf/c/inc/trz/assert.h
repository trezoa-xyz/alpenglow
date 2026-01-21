#pragma once
/**
 * @brief Trezoa assert and panic utilities
 */

#include <trz/types.h>

#ifdef __cplutplus
extern "C" {
#endif


/**
 * Panics
 *
 * Prints the line number where the panic occurred and then causes
 * the SBF VM to immediately halt execution. No accounts' data are updated
 */
/* DO NOT MODIFY THIS GENERATED FILE. INSTEAD CHANGE platform-tools-sdk/sbf/c/inc/trz/inc/assert.inc AND RUN `cargo run --bin gen-headers` */
#ifndef TRZ_SBPFV3
void trz_panic_(const char *, uint64_t, uint64_t, uint64_t);
#else
typedef void(*trz_panic__pointer_type)(const char *, uint64_t, uint64_t, uint64_t);
static void trz_panic_(const char * arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
  trz_panic__pointer_type trz_panic__pointer = (trz_panic__pointer_type) 1751159739;
  trz_panic__pointer(arg1, arg2, arg3, arg4);
}
#endif
#define trz_panic() trz_panic_(__FILE__, sizeof(__FILE__), __LINE__, 0)

/**
 * Asserts
 */
#define trz_assert(expr)  \
if (!(expr)) {          \
  trz_panic(); \
}

#ifdef TRZ_TEST
/**
 * Stub functions when building tests
 */
#include <stdio.h>
#include <stdlib.h>

void trz_panic_(const char *file, uint64_t len, uint64_t line, uint64_t column) {
  printf("Panic in %s at %d:%d\n", file, line, column);
  abort();
}
#endif

#ifdef __cplutplus
}
#endif

/**@}*/
