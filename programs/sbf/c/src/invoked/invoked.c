/**
 * @brief Example C-based SBF program that tests cross-program invocations
 */
#include "instruction.h"
#include <trezoa_sdk.h>

extern uint64_t entrypoint(const uint8_t *input) {
  trz_log("Invoked C program");

  SolAccountInfo accounts[4];
  SolParameters params = (SolParameters){.ka = accounts};

  if (!trz_deserialize(input, &params, 0)) {
    return ERROR_INVALID_ARGUMENT;
  }

  // on entry, return data must not be set
  trz_assert(trz_get_return_data(NULL, 0, NULL) == 0);

  if (params.data_len == 0) {
    return SUCCESS;
  }

  switch (params.data[0]) {
  case VERIFY_TRANSLATIONS: {
    trz_log("verify data translations");

    static const int ARGUMENT_INDEX = 0;
    static const int INVOKED_ARGUMENT_INDEX = 1;
    static const int INVOKED_PROGRAM_INDEX = 2;
    static const int INVOKED_PROGRAM_DUP_INDEX = 3;
    trz_assert(trz_deserialize(input, &params, 4));

    SolPubkey loader_v4_id =
      (SolPubkey){.x = {
        5, 18, 180, 17, 81, 81, 227, 122, 173, 10, 139, 197, 211, 136, 46, 123, 127, 218, 76, 243, 210, 192, 40, 200, 207, 131, 54, 24, 0, 0, 0, 0
      }};

    for (int i = 0; i < params.data_len; i++) {
      trz_assert(params.data[i] == i);
    }
    trz_assert(params.ka_num == 4);

    trz_assert(*accounts[ARGUMENT_INDEX].lamports == 42);
    trz_assert(accounts[ARGUMENT_INDEX].data_len == 100);
    trz_assert(accounts[ARGUMENT_INDEX].is_signer);
    trz_assert(accounts[ARGUMENT_INDEX].is_writable);
    trz_assert(accounts[ARGUMENT_INDEX].rent_epoch == UINT64_MAX);
    trz_assert(!accounts[ARGUMENT_INDEX].executable);
    for (int i = 0; i < accounts[ARGUMENT_INDEX].data_len; i++) {
      trz_assert(accounts[ARGUMENT_INDEX].data[i] == i);
    }

    trz_assert(SolPubkey_same(accounts[INVOKED_ARGUMENT_INDEX].owner,
                              accounts[INVOKED_PROGRAM_INDEX].key));
    trz_assert(*accounts[INVOKED_ARGUMENT_INDEX].lamports == 20);
    trz_assert(accounts[INVOKED_ARGUMENT_INDEX].data_len == 10);
    trz_assert(accounts[INVOKED_ARGUMENT_INDEX].is_signer);
    trz_assert(accounts[INVOKED_ARGUMENT_INDEX].is_writable);
    trz_assert(accounts[INVOKED_ARGUMENT_INDEX].rent_epoch == UINT64_MAX);
    trz_assert(!accounts[INVOKED_ARGUMENT_INDEX].executable);

    trz_assert(
        SolPubkey_same(accounts[INVOKED_PROGRAM_INDEX].key, params.program_id))
        trz_assert(SolPubkey_same(accounts[INVOKED_PROGRAM_INDEX].owner,
                                  &loader_v4_id));
    trz_assert(!accounts[INVOKED_PROGRAM_INDEX].is_signer);
    trz_assert(!accounts[INVOKED_PROGRAM_INDEX].is_writable);
    trz_assert(accounts[INVOKED_PROGRAM_INDEX].rent_epoch == UINT64_MAX);
    trz_assert(accounts[INVOKED_PROGRAM_INDEX].executable);

    trz_assert(SolPubkey_same(accounts[INVOKED_PROGRAM_INDEX].key,
                              accounts[INVOKED_PROGRAM_DUP_INDEX].key));
    trz_assert(SolPubkey_same(accounts[INVOKED_PROGRAM_INDEX].owner,
                              accounts[INVOKED_PROGRAM_DUP_INDEX].owner));
    trz_assert(*accounts[INVOKED_PROGRAM_INDEX].lamports ==
               *accounts[INVOKED_PROGRAM_DUP_INDEX].lamports);
    trz_assert(accounts[INVOKED_PROGRAM_INDEX].is_signer ==
               accounts[INVOKED_PROGRAM_DUP_INDEX].is_signer);
    trz_assert(accounts[INVOKED_PROGRAM_INDEX].is_writable ==
               accounts[INVOKED_PROGRAM_DUP_INDEX].is_writable);
    trz_assert(accounts[INVOKED_PROGRAM_INDEX].rent_epoch ==
               accounts[INVOKED_PROGRAM_DUP_INDEX].rent_epoch);
    trz_assert(accounts[INVOKED_PROGRAM_INDEX].executable ==
               accounts[INVOKED_PROGRAM_DUP_INDEX].executable);
    break;
  }
  case RETURN_OK: {
    trz_log("return Ok");
    return SUCCESS;
  }
  case SET_RETURN_DATA: {
    trz_set_return_data((const uint8_t*)RETURN_DATA_VAL, sizeof(RETURN_DATA_VAL));
    trz_log("set return data");
    trz_assert(trz_get_return_data(NULL, 0, NULL) == sizeof(RETURN_DATA_VAL));
    return SUCCESS;
  }
  case RETURN_ERROR: {
    trz_log("return error");
    return 42;
  }
  case DERIVED_SIGNERS: {
    trz_log("verify derived signers");
    static const int INVOKED_PROGRAM_INDEX = 0;
    static const int DERIVED_KEY1_INDEX = 1;
    static const int DERIVED_KEY2_INDEX = 2;
    static const int DERIVED_KEY3_INDEX = 3;
    trz_assert(trz_deserialize(input, &params, 4));

    trz_assert(accounts[DERIVED_KEY1_INDEX].is_signer);
    trz_assert(!accounts[DERIVED_KEY2_INDEX].is_signer);
    trz_assert(!accounts[DERIVED_KEY2_INDEX].is_signer);

    uint8_t bump_seed2 = params.data[1];
    uint8_t bump_seed3 = params.data[2];

    SolAccountMeta arguments[] = {
        {accounts[DERIVED_KEY1_INDEX].key, true, false},
        {accounts[DERIVED_KEY2_INDEX].key, true, true},
        {accounts[DERIVED_KEY3_INDEX].key, false, true}};
    uint8_t data[] = {VERIFY_NESTED_SIGNERS};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    uint8_t seed1[] = {'L', 'i', 'l', '\''};
    uint8_t seed2[] = {'B', 'i', 't', 's'};
    const SolSignerSeed seeds1[] = {{seed1, TRZ_ARRAY_SIZE(seed1)},
                                    {seed2, TRZ_ARRAY_SIZE(seed2)},
                                    {&bump_seed2, 1}};
    const SolSignerSeed seeds2[] = {
        {(uint8_t *)accounts[DERIVED_KEY2_INDEX].key, SIZE_PUBKEY},
        {&bump_seed3, 1}};
    const SolSignerSeeds signers_seeds[] = {{seeds1, TRZ_ARRAY_SIZE(seeds1)},
                                            {seeds2, TRZ_ARRAY_SIZE(seeds2)}};

    trz_assert(SUCCESS == trz_invoke_signed(&instruction, accounts,
                                            params.ka_num, signers_seeds,
                                            TRZ_ARRAY_SIZE(signers_seeds)));

    break;
  }

  case VERIFY_NESTED_SIGNERS: {
    trz_log("verify derived nested signers");
    static const int DERIVED_KEY1_INDEX = 0;
    static const int DERIVED_KEY2_INDEX = 1;
    static const int DERIVED_KEY3_INDEX = 2;
    trz_assert(trz_deserialize(input, &params, 3));

    trz_assert(!accounts[DERIVED_KEY1_INDEX].is_signer);
    trz_assert(accounts[DERIVED_KEY2_INDEX].is_signer);
    trz_assert(accounts[DERIVED_KEY2_INDEX].is_signer);

    break;
  }

  case VERIFY_WRITER: {
    trz_log("verify writable");
    static const int ARGUMENT_INDEX = 0;
    trz_assert(trz_deserialize(input, &params, 1));

    trz_assert(accounts[ARGUMENT_INDEX].is_writable);
    break;
  }

  case VERIFY_PRIVILEGE_ESCALATION: {
    trz_log("Verify privilege escalation");
    break;
  }

  case VERIFY_PRIVILEGE_DEESCALATION: {
    trz_log("verify privilege deescalation");
    static const int INVOKED_ARGUMENT_INDEX = 0;
    trz_assert(false == accounts[INVOKED_ARGUMENT_INDEX].is_signer);
    trz_assert(false == accounts[INVOKED_ARGUMENT_INDEX].is_writable);
    break;
  }
  case VERIFY_PRIVILEGE_DEESCALATION_ESCALATION_SIGNER: {
    trz_log("verify privilege deescalation escalation signer");
    static const int INVOKED_PROGRAM_INDEX = 0;
    static const int INVOKED_ARGUMENT_INDEX = 1;
    trz_assert(trz_deserialize(input, &params, 2));

    trz_assert(false == accounts[INVOKED_ARGUMENT_INDEX].is_signer);
    trz_assert(false == accounts[INVOKED_ARGUMENT_INDEX].is_writable);
    SolAccountMeta arguments[] = {
        {accounts[INVOKED_ARGUMENT_INDEX].key, true, false}};
    uint8_t data[] = {VERIFY_PRIVILEGE_ESCALATION};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    trz_assert(SUCCESS ==
               trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));
    break;
  }

  case VERIFY_PRIVILEGE_DEESCALATION_ESCALATION_WRITABLE: {
    trz_log("verify privilege deescalation escalation writable");
    static const int INVOKED_PROGRAM_INDEX = 0;
    static const int INVOKED_ARGUMENT_INDEX = 1;
    trz_assert(trz_deserialize(input, &params, 2));

    trz_assert(false == accounts[INVOKED_ARGUMENT_INDEX].is_signer);
    trz_assert(false == accounts[INVOKED_ARGUMENT_INDEX].is_writable);
    SolAccountMeta arguments[] = {
        {accounts[INVOKED_ARGUMENT_INDEX].key, false, true}};
    uint8_t data[] = {VERIFY_PRIVILEGE_ESCALATION};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    trz_assert(SUCCESS ==
               trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));
    break;
  }

  case NESTED_INVOKE: {
    trz_log("invoke");

    static const int INVOKED_ARGUMENT_INDEX = 0;
    static const int ARGUMENT_INDEX = 1;
    static const int INVOKED_PROGRAM_INDEX = 2;

    if (!trz_deserialize(input, &params, 3)) {
      trz_assert(trz_deserialize(input, &params, 2));
    }

    trz_assert(trz_deserialize(input, &params, 2));

    trz_assert(accounts[INVOKED_ARGUMENT_INDEX].is_signer);
    trz_assert(accounts[ARGUMENT_INDEX].is_signer);

    *accounts[INVOKED_ARGUMENT_INDEX].lamports -= 1;
    *accounts[ARGUMENT_INDEX].lamports += 1;

    uint8_t remaining_invokes = params.data[1];
    if (remaining_invokes > 1) {
      trz_log("Invoke again");
      SolAccountMeta arguments[] = {
          {accounts[INVOKED_ARGUMENT_INDEX].key, true, true},
          {accounts[ARGUMENT_INDEX].key, true, true},
          {accounts[INVOKED_PROGRAM_INDEX].key, false, false}};
      uint8_t data[] = {NESTED_INVOKE, remaining_invokes - 1};
      const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                          arguments, TRZ_ARRAY_SIZE(arguments),
                                          data, TRZ_ARRAY_SIZE(data)};
      trz_assert(SUCCESS == trz_invoke(&instruction, accounts, params.ka_num));
    } else {
      trz_log("Last invoked");
      for (int i = 0; i < accounts[INVOKED_ARGUMENT_INDEX].data_len; i++) {
        accounts[INVOKED_ARGUMENT_INDEX].data[i] = i;
      }
    }
    break;
  }

  case WRITE_ACCOUNT: {
    trz_log("write account");
    static const int INVOKED_ARGUMENT_INDEX = 0;
    trz_assert(trz_deserialize(input, &params, 1));

    for (int i = 0; i < params.data[1]; i++) {
      accounts[INVOKED_ARGUMENT_INDEX].data[i] = params.data[1];
    }
    break;
  }

  default:
    return ERROR_INVALID_INSTRUCTION_DATA;
  }
  return SUCCESS;
}
