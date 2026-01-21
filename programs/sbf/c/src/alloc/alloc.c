/**
 * @brief Example C-based SBF sanity rogram that prints out the parameters
 * passed to it
 */
#include <trezoa_sdk.h>

extern uint64_t entrypoint(const uint8_t *input) {
  {
    // Confirm large allocation fails
    void *ptr = trz_calloc(1, UINT64_MAX);
    if (ptr != NULL) {
      trz_log("Error: Alloc of very large type should fail");
      trz_panic();
    }
  }

  {
    // Confirm large allocation fails
    void *ptr = trz_calloc(UINT64_MAX, 1);
    if (ptr != NULL) {
      trz_log("Error: Alloc of very large number of items should fail");
      trz_panic();
    }
  }

  {
    // Test modest allocation and de-allocation
    void *ptr = trz_calloc(1, 100);
    if (ptr == NULL) {
      trz_log("Error: Alloc of 100 bytes failed");
      trz_panic();
    }
    trz_free(ptr);
  }

  {
    // Test allocated memory read and write

    const uint64_t iters = 100;
    uint8_t *ptr = trz_calloc(1, iters);
    if (ptr == NULL) {
      trz_log("Error: Alloc failed");
      trz_panic();
    }
    for (uint64_t i = 0; i < iters; i++) {
      *(ptr + i) = i;
    }
    for (uint64_t i = 0; i < iters; i++) {
      trz_assert(*(ptr + i) == i);
    }
    trz_assert(*(ptr + 42) == 42);
    trz_free(ptr);
  }

  // Alloc to exhaustion

  for (uint64_t i = 0; i < 31; i++) {
    uint8_t *ptr = trz_calloc(1024, 1);
    if (ptr == NULL) {
      trz_log("large alloc failed");
      trz_panic();
    }
  }
  for (uint64_t i = 0; i < 760; i++) {
    uint8_t *ptr = trz_calloc(1, 1);
    if (ptr == NULL) {
      trz_log("small alloc failed");
      trz_panic();
    }
  }
  uint8_t *ptr = trz_calloc(1, 1);
  if (ptr != NULL) {
    trz_log("final alloc did not fail");
    trz_panic();
  }

  return SUCCESS;
}
