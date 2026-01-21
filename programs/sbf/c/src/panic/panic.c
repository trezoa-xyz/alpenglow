/**
 * @brief Example C-based SBF program that prints out the parameters
 * passed to it
 */
#include <trezoa_sdk.h>

extern uint64_t entrypoint(const uint8_t *input) {
  trz_panic();
  return SUCCESS;
}
