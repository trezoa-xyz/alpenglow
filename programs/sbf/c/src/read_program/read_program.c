#include <trezoa_sdk.h>

extern uint64_t entrypoint(const uint8_t *input) {
  SolAccountInfo ka[1];
  SolParameters params = (SolParameters){.ka = ka};

  trz_log(__FILE__);

  if (!trz_deserialize(input, &params, TRZ_ARRAY_SIZE(ka))) {
    return ERROR_INVALID_ARGUMENT;
  }

  trz_assert(params.ka_num == 1);
  trz_assert(!trz_memcmp(params.ka[0].data, params.data, params.data_len));
  trz_assert(params.ka[0].is_signer == false);
  trz_assert(params.ka[0].is_writable == false);
  trz_assert(params.ka[0].executable == true);

  return SUCCESS;
}
