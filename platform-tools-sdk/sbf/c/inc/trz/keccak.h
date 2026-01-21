#pragma once
/**
 * @brief Trezoa keccak system call
**/

#include <trz/types.h>

#ifdef __cplutplus
extern "C" {
#endif

/**
 * Length of a Keccak hash result
 */
#define KECCAK_RESULT_LENGTH 32

/**
 * Keccak
 *
 * @param bytes Array of byte arrays
 * @param bytes_len Number of byte arrays
 * @param result 32 byte array to hold the result
 */
/* DO NOT MODIFY THIS GENERATED FILE. INSTEAD CHANGE platform-tools-sdk/sbf/c/inc/trz/inc/keccak.inc AND RUN `cargo run --bin gen-headers` */
#ifndef TRZ_SBPFV3
uint64_t trz_keccak256(const SolBytes *, int, uint8_t *);
#else
typedef uint64_t(*trz_keccak256_pointer_type)(const SolBytes *, int, uint8_t *);
static uint64_t trz_keccak256(const SolBytes * arg1, int arg2, uint8_t * arg3) {
  trz_keccak256_pointer_type trz_keccak256_pointer = (trz_keccak256_pointer_type) 3615046331;
  return trz_keccak256_pointer(arg1, arg2, arg3);
}
#endif

#ifdef __cplutplus
}
#endif

/**@}*/
