/**
 * @brief Example C-based SBF sanity rogram that prints out the parameters
 * passed to it
 */
#include <trezoa_sdk.h>

extern uint64_t entrypoint(const uint8_t *input) {
  SolAccountInfo ka[1];
  SolParameters params = (SolParameters) { .ka = ka };

  trz_log(__FILE__);

  if (!trz_deserialize(input, &params, TRZ_ARRAY_SIZE(ka))) {
    return ERROR_INVALID_ARGUMENT;
  }

  // Log the provided input parameters.  In the case of  the no-op
  // program, no account keys or input data are expected but real
  // programs will have specific requirements so they can do their work.
  trz_log_params(&params);

  trz_log_compute_units();
  return SUCCESS;
}
