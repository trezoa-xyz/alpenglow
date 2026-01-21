#pragma once
/**
 * @brief Trezoa logging utilities
 */

#include <trz/types.h>
#include <trz/string.h>
#include <trz/entrypoint.h>

#ifdef __cplutplus
extern "C" {
#endif

/**
 * Prints a string to stdout
 */
/* DO NOT MODIFY THIS GENERATED FILE. INSTEAD CHANGE platform-tools-sdk/sbf/c/inc/trz/inc/compute_units.inc AND RUN `cargo run --bin gen-headers` */
#ifndef TRZ_SBPFV3
uint64_t trz_remaining_compute_units();
#else
typedef uint64_t(*trz_remaining_compute_units_pointer_type)();
static uint64_t trz_remaining_compute_units() {
  trz_remaining_compute_units_pointer_type trz_remaining_compute_units_pointer = (trz_remaining_compute_units_pointer_type) 3991886574;
  return trz_remaining_compute_units_pointer();
}
#endif

#ifdef TRZ_TEST
/**
 * Stub functions when building tests
 */

uint64_t trz_remaining_compute_units() {
  return UINT64_MAX;
}
#endif

#ifdef __cplutplus
}
#endif

/**@}*/
