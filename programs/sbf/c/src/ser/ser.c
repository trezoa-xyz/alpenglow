/**
 * @brief Example C-based SBF sanity rogram that prints out the parameters
 * passed to it
 */
#include <trezoa_sdk.h>

extern uint64_t entrypoint(const uint8_t *input) {
  SolAccountInfo ka[2];
  SolParameters params = (SolParameters){.ka = ka};

  trz_log(__FILE__);

  if (!trz_deserialize(input, &params, TRZ_ARRAY_SIZE(ka))) {
    return ERROR_INVALID_ARGUMENT;
  }

  char ka_data[] = {1, 2, 3};
  SolPubkey ka_owner;
  trz_memset(ka_owner.x, 0, SIZE_PUBKEY); // set to system program

  trz_assert(params.ka_num == 2);
  for (int i = 0; i < 2; i++) {
    trz_assert(*params.ka[i].lamports == 42);
    trz_assert(!trz_memcmp(params.ka[i].data, ka_data, 4));
    trz_assert(SolPubkey_same(params.ka[i].owner, &ka_owner));
    trz_assert(params.ka[i].is_signer == false);
    trz_assert(params.ka[i].is_writable == false);
    trz_assert(params.ka[i].executable == false);
  }

  char data[] = {4, 5, 6, 7};
  trz_assert(params.data_len = 4);
  trz_assert(!trz_memcmp(params.data, data, 4));

  return SUCCESS;
}
