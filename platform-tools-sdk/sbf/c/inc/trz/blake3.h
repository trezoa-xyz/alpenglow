#pragma once
/**
 * @brief Trezoa Blake3 system call
 */

#include <trz/types.h>

#ifdef __cplutplus
extern "C" {
#endif

/**
 * Length of a Blake3 hash result
 */
#define BLAKE3_RESULT_LENGTH 32

/**
 * Blake3
 *
 * @param bytes Array of byte arrays
 * @param bytes_len Number of byte arrays
 * @param result 32 byte array to hold the result
 */
/* DO NOT MODIFY THIS GENERATED FILE. INSTEAD CHANGE platform-tools-sdk/sbf/c/inc/trz/inc/blake3.inc AND RUN `cargo run --bin gen-headers` */
#ifndef TRZ_SBPFV3
uint64_t trz_blake3(const SolBytes *, int, const uint8_t *);
#else
typedef uint64_t(*trz_blake3_pointer_type)(const SolBytes *, int, const uint8_t *);
static uint64_t trz_blake3(const SolBytes * arg1, int arg2, const uint8_t * arg3) {
  trz_blake3_pointer_type trz_blake3_pointer = (trz_blake3_pointer_type) 390877474;
  return trz_blake3_pointer(arg1, arg2, arg3);
}
#endif

#ifdef __cplutplus
}
#endif

/**@}*/
