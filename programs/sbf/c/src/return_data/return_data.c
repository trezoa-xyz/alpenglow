/**
 * @brief return data Syscall test
 */
#include <trezoa_sdk.h>

#define DATA "the quick brown fox jumps over the lazy dog"

extern uint64_t entrypoint(const uint8_t *input) {
  uint8_t buf[1024];
  SolPubkey me;

  // There should be no return data on entry
  uint64_t ret = trz_get_return_data(NULL, 0, NULL);

  trz_assert(ret == 0);

  // set some return data
  trz_set_return_data((const uint8_t*)DATA, sizeof(DATA));

  // ensure the length is correct
  ret = trz_get_return_data(NULL, 0, &me);
  trz_assert(ret == sizeof(DATA));

  // try getting a subset
  ret = trz_get_return_data(buf, 4, &me);

  trz_assert(ret == sizeof(DATA));

  trz_assert(!trz_memcmp(buf, "the ", 4));

  // try getting the whole thing
  ret = trz_get_return_data(buf, sizeof(buf), &me);

  trz_assert(ret == sizeof(DATA));

  trz_assert(!trz_memcmp(buf, (const uint8_t*)DATA, sizeof(DATA)));

  // done
  return SUCCESS;
}
