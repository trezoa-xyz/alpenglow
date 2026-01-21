/**
 * @brief Example C based SBF program that prints out the parameters
 * passed to it
 */
#include <trz/deserialize.h>


extern uint64_t entrypoint(const uint8_t *input) {
  SolAccountInfo ka[1];
  SolParameters params = (SolParameters) { .ka = ka };

  if (!trz_deserialize(input, &params, TRZ_ARRAY_SIZE(ka))) {
    return ERROR_INVALID_ARGUMENT;
  }

  return SUCCESS;
}
