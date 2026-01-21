#pragma once
/**
 * @brief Trezoa return data system calls
**/

#include <trz/types.h>
#include <trz/pubkey.h>

#ifdef __cplutplus
extern "C"
{
#endif

/**
 * Maximum size of return data
 */
#define MAX_RETURN_DATA 1024

/**
 * Set the return data
 *
 * @param bytes byte array to set
 * @param bytes_len length of byte array. This may not exceed MAX_RETURN_DATA.
 */
/* DO NOT MODIFY THIS GENERATED FILE. INSTEAD CHANGE platform-tools-sdk/sbf/c/inc/trz/inc/return_data.inc AND RUN `cargo run --bin gen-headers` */
#ifndef TRZ_SBPFV3
void trz_set_return_data(const uint8_t *, uint64_t);
#else
typedef void(*trz_set_return_data_pointer_type)(const uint8_t *, uint64_t);
static void trz_set_return_data(const uint8_t * arg1, uint64_t arg2) {
  trz_set_return_data_pointer_type trz_set_return_data_pointer = (trz_set_return_data_pointer_type) 2720453611;
  trz_set_return_data_pointer(arg1, arg2);
}
#endif

/**
 * Get the return data
 *
 * @param bytes byte buffer
 * @param bytes_len maximum length of buffer
 * @param program_id the program_id which set the return data. Only set if there was some return data (the function returns non-zero).
 * @param result length of return data (may exceed bytes_len if the return data is longer)
 */
/* DO NOT MODIFY THIS GENERATED FILE. INSTEAD CHANGE platform-tools-sdk/sbf/c/inc/trz/inc/return_data.inc AND RUN `cargo run --bin gen-headers` */
#ifndef TRZ_SBPFV3
uint64_t trz_get_return_data(uint8_t *, uint64_t, SolPubkey *);
#else
typedef uint64_t(*trz_get_return_data_pointer_type)(uint8_t *, uint64_t, SolPubkey *);
static uint64_t trz_get_return_data(uint8_t * arg1, uint64_t arg2, SolPubkey * arg3) {
  trz_get_return_data_pointer_type trz_get_return_data_pointer = (trz_get_return_data_pointer_type) 1562527204;
  return trz_get_return_data_pointer(arg1, arg2, arg3);
}
#endif

#ifdef __cplutplus
}
#endif

/**@}*/
