/**
 * @brief test program that generates SBF PC relative call instructions
 */
#include <trezoa_sdk.h>

void __attribute__ ((noinline)) helper() {
  trz_log(__func__);
}

extern uint64_t entrypoint(const uint8_t *input) {
  trz_log(__func__);
  helper();
  return SUCCESS;
}
