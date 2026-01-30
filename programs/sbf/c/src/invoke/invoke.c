/**
 * @brief Example C-based SBF program that tests cross-program invocations
 */
#include "../invoked/instruction.h"
#include <trz/entrypoint.h>
#include <trz/cpi.h>
#include <trz/pubkey.h>
#include <trz/log.h>
#include <trz/assert.h>
#include <trz/deserialize.h>
#include <trz/return_data.h>

static const uint8_t TEST_SUCCESS = 1;
static const uint8_t TEST_PRIVILEGE_ESCALATION_SIGNER = 2;
static const uint8_t TEST_PRIVILEGE_ESCALATION_WRITABLE = 3;
static const uint8_t TEST_PPROGRAM_NOT_OWNED_BY_LOADER = 4;
static const uint8_t TEST_PPROGRAM_NOT_EXECUTABLE = 5;
static const uint8_t TEST_EMPTY_ACCOUNTS_SLICE = 6;
static const uint8_t TEST_CAP_SEEDS = 7;
static const uint8_t TEST_CAP_SIGNERS = 8;
static const uint8_t TEST_ALLOC_ACCESS_VIOLATION = 9;
static const uint8_t TEST_MAX_INSTRUCTION_DATA_LEN_EXCEEDED = 10;
static const uint8_t TEST_MAX_INSTRUCTION_ACCOUNTS_EXCEEDED = 11;
static const uint8_t TEST_RETURN_ERROR = 12;
static const uint8_t TEST_PRIVILEGE_DEESCALATION_ESCALATION_SIGNER = 13;
static const uint8_t TEST_PRIVILEGE_DEESCALATION_ESCALATION_WRITABLE = 14;
static const uint8_t TEST_WRITABLE_DEESCALATION_WRITABLE = 15;
static const uint8_t TEST_NESTED_INVOKE_TOO_DEEP = 16;
static const uint8_t TEST_CALL_PRECOMPILE = 17;
static const uint8_t ADD_LAMPORTS = 18;
static const uint8_t TEST_RETURN_DATA_TOO_LARGE = 19;
static const uint8_t TEST_DUPLICATE_PRIVILEGE_ESCALATION_SIGNER = 20;
static const uint8_t TEST_DUPLICATE_PRIVILEGE_ESCALATION_WRITABLE = 21;
static const uint8_t TEST_MAX_ACCOUNT_INFOS_EXCEEDED = 22;
// TEST_CPI_INVALID_* must match the definitions in
// https://github.com/trezoa-team/trezoa/blob/master/programs/sbf/rust/invoke/src/instructions.rs
static const uint8_t TEST_CPI_INVALID_KEY_POINTER = 35;
static const uint8_t TEST_CPI_INVALID_OWNER_POINTER = 36;
static const uint8_t TEST_CPI_INVALID_LAMPORTS_POINTER = 37;
static const uint8_t TEST_CPI_INVALID_DATA_POINTER = 38;
static const uint8_t TEST_WRITE_ACCOUNT = 40;
static const uint8_t TEST_ACCOUNT_INFO_IN_ACCOUNT = 43;
static const uint8_t TEST_NESTED_INVOKE_SIMD_0268_OK = 46;
static const uint8_t TEST_NESTED_INVOKE_SIMD_0268_TOO_DEEP = 47;

static const int MINT_INDEX = 0;
static const int ARGUMENT_INDEX = 1;
static const int INVOKED_PROGRAM_INDEX = 2;
static const int INVOKED_ARGUMENT_INDEX = 3;
static const int INVOKED_PROGRAM_DUP_INDEX = 4;
static const int ARGUMENT_DUP_INDEX = 5;
static const int DERIVED_KEY1_INDEX = 6;
static const int DERIVED_KEY2_INDEX = 7;
static const int DERIVED_KEY3_INDEX = 8;
static const int SYSTEM_PROGRAM_INDEX = 9;
static const int FROM_INDEX = 10;
static const int ED25519_PROGRAM_INDEX = 11;
static const int INVOKE_PROGRAM_INDEX = 12;
static const int UNEXECUTABLE_PROGRAM_INDEX = 13;

uint64_t do_nested_invokes(uint64_t num_nested_invokes,
                           SolAccountInfo *accounts, uint64_t num_accounts) {
  trz_assert(accounts[ARGUMENT_INDEX].is_signer);

  *accounts[ARGUMENT_INDEX].lamports -= 5;
  *accounts[INVOKED_ARGUMENT_INDEX].lamports += 5;

  SolAccountMeta arguments[] = {
      {accounts[INVOKED_ARGUMENT_INDEX].key, true, true},
      {accounts[ARGUMENT_INDEX].key, true, true},
      {accounts[INVOKED_PROGRAM_INDEX].key, false, false}};
  uint8_t data[] = {NESTED_INVOKE, num_nested_invokes};
  const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                      arguments, TRZ_ARRAY_SIZE(arguments),
                                      data, TRZ_ARRAY_SIZE(data)};

  trz_log("First invoke");
  trz_assert(SUCCESS == trz_invoke(&instruction, accounts, num_accounts));
  trz_log("2nd invoke from first program");
  trz_assert(SUCCESS == trz_invoke(&instruction, accounts, num_accounts));

  trz_assert(*accounts[ARGUMENT_INDEX].lamports ==
             42 - 5 + (2 * num_nested_invokes));
  trz_assert(*accounts[INVOKED_ARGUMENT_INDEX].lamports ==
             20 + 5 - (2 * num_nested_invokes));

  return SUCCESS;
}

extern uint64_t entrypoint(const uint8_t *input) {
  trz_log("invoke C program");

  SolAccountInfo accounts[14];
  SolParameters params = (SolParameters){.ka = accounts};

  if (!trz_deserialize(input, &params, TRZ_ARRAY_SIZE(accounts))) {
    return ERROR_INVALID_ARGUMENT;
  }

  uint8_t bump_seed1 = params.data[1];
  uint8_t bump_seed2 = params.data[2];
  uint8_t bump_seed3 = params.data[3];

  switch (params.data[0]) {
  case TEST_SUCCESS: {
    trz_log("Call system program create account");
    {
      uint64_t from_lamports = *accounts[FROM_INDEX].lamports;
      uint64_t to_lamports = *accounts[DERIVED_KEY1_INDEX].lamports;
      SolAccountMeta arguments[] = {
          {accounts[FROM_INDEX].key, true, true},
          {accounts[DERIVED_KEY1_INDEX].key, true, true}};
      uint8_t data[4 + 8 + 8 + 32];
      *(uint64_t *)(data + 4) = 42;
      *(uint64_t *)(data + 4 + 8) = MAX_PERMITTED_DATA_INCREASE;
      trz_memcpy(data + 4 + 8 + 8, params.program_id, SIZE_PUBKEY);
      const SolInstruction instruction = {accounts[SYSTEM_PROGRAM_INDEX].key,
                                          arguments, TRZ_ARRAY_SIZE(arguments),
                                          data, TRZ_ARRAY_SIZE(data)};
      uint8_t seed1[] = {'Y', 'o', 'u', ' ', 'p', 'a', 's', 's',
                         ' ', 'b', 'u', 't', 't', 'e', 'r'};
      const SolSignerSeed seeds1[] = {{seed1, TRZ_ARRAY_SIZE(seed1)},
                                      {&bump_seed1, 1}};
      const SolSignerSeeds signers_seeds[] = {{seeds1, TRZ_ARRAY_SIZE(seeds1)}};
      trz_assert(SUCCESS == trz_invoke_signed(&instruction, accounts,
                                              TRZ_ARRAY_SIZE(accounts),
                                              signers_seeds,
                                              TRZ_ARRAY_SIZE(signers_seeds)));
      trz_assert(*accounts[FROM_INDEX].lamports == from_lamports - 42);
      trz_assert(*accounts[DERIVED_KEY1_INDEX].lamports == to_lamports + 42);
      trz_assert(SolPubkey_same(accounts[DERIVED_KEY1_INDEX].owner,
                                params.program_id));
      trz_assert(accounts[DERIVED_KEY1_INDEX].data_len ==
                 MAX_PERMITTED_DATA_INCREASE);
      trz_assert(
          accounts[DERIVED_KEY1_INDEX].data[MAX_PERMITTED_DATA_INCREASE - 1] ==
          0);
      accounts[DERIVED_KEY1_INDEX].data[MAX_PERMITTED_DATA_INCREASE - 1] = 0x0f;
      trz_assert(
          accounts[DERIVED_KEY1_INDEX].data[MAX_PERMITTED_DATA_INCREASE - 1] ==
          0x0f);
      for (uint8_t i = 0; i < 20; i++) {
        accounts[DERIVED_KEY1_INDEX].data[i] = i;
      }
    }

    trz_log("Call system program transfer");
    {
      uint64_t from_lamports = *accounts[FROM_INDEX].lamports;
      uint64_t to_lamports = *accounts[DERIVED_KEY1_INDEX].lamports;
      SolAccountMeta arguments[] = {
          {accounts[FROM_INDEX].key, true, true},
          {accounts[DERIVED_KEY1_INDEX].key, true, false}};
      uint8_t data[] = {2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0};
      const SolInstruction instruction = {accounts[SYSTEM_PROGRAM_INDEX].key,
                                          arguments, TRZ_ARRAY_SIZE(arguments),
                                          data, TRZ_ARRAY_SIZE(data)};
      trz_assert(SUCCESS ==
                 trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));
      trz_assert(*accounts[FROM_INDEX].lamports == from_lamports - 1);
      trz_assert(*accounts[DERIVED_KEY1_INDEX].lamports == to_lamports + 1);
    }

    trz_log("Test data translation");
    {
      for (int i = 0; i < accounts[ARGUMENT_INDEX].data_len; i++) {
        accounts[ARGUMENT_INDEX].data[i] = i;
      }

      SolAccountMeta arguments[] = {
          {accounts[ARGUMENT_INDEX].key, true, true},
          {accounts[INVOKED_ARGUMENT_INDEX].key, true, true},
          {accounts[INVOKED_PROGRAM_INDEX].key, false, false},
          {accounts[INVOKED_PROGRAM_DUP_INDEX].key, false, false}};
      uint8_t data[] = {VERIFY_TRANSLATIONS, 1, 2, 3, 4, 5};
      const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                          arguments, TRZ_ARRAY_SIZE(arguments),
                                          data, TRZ_ARRAY_SIZE(data)};

      trz_assert(SUCCESS ==
                 trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));
    }

    trz_log("Test no instruction data");
    {
      SolAccountMeta arguments[] = {{accounts[ARGUMENT_INDEX].key, true, true}};
      uint8_t data[] = {};
      const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                          arguments, TRZ_ARRAY_SIZE(arguments),
                                          data, TRZ_ARRAY_SIZE(data)};

      trz_assert(SUCCESS ==
                 trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));
    }

    trz_log("Test return data");
    {
      SolAccountMeta arguments[] = {{accounts[ARGUMENT_INDEX].key, true, true}};
      uint8_t data[] = { SET_RETURN_DATA };
      uint8_t buf[100];

      const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                          arguments, TRZ_ARRAY_SIZE(arguments),
                                          data, TRZ_ARRAY_SIZE(data)};

      // set some return data, so that the callee can check it is cleared
      trz_set_return_data((uint8_t[]){1, 2, 3, 4}, 4);

      trz_assert(SUCCESS ==
                 trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));

      SolPubkey setter;

      uint64_t ret = trz_get_return_data(data, sizeof(data), &setter);

      trz_assert(ret == sizeof(RETURN_DATA_VAL));

      trz_assert(trz_memcmp(data, RETURN_DATA_VAL, sizeof(RETURN_DATA_VAL)));
      trz_assert(SolPubkey_same(&setter, accounts[INVOKED_PROGRAM_INDEX].key));
    }

    trz_log("Test create_program_address");
    {
      uint8_t seed1[] = {'Y', 'o', 'u', ' ', 'p', 'a', 's', 's',
                         ' ', 'b', 'u', 't', 't', 'e', 'r'};
      const SolSignerSeed seeds1[] = {{seed1, TRZ_ARRAY_SIZE(seed1)},
                                      {&bump_seed1, 1}};
      SolPubkey address;
      trz_assert(SUCCESS ==
                 trz_create_program_address(seeds1, TRZ_ARRAY_SIZE(seeds1),
                                            params.program_id, &address));
      trz_assert(SolPubkey_same(&address, accounts[DERIVED_KEY1_INDEX].key));
    }

    trz_log("Test try_find_program_address");
    {
      uint8_t seed[] = {'Y', 'o', 'u', ' ', 'p', 'a', 's', 's',
                        ' ', 'b', 'u', 't', 't', 'e', 'r'};
      const SolSignerSeed seeds[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
      SolPubkey address;
      uint8_t bump_seed;
      trz_assert(SUCCESS == trz_try_find_program_address(
                                seeds, TRZ_ARRAY_SIZE(seeds), params.program_id,
                                &address, &bump_seed));
      trz_assert(SolPubkey_same(&address, accounts[DERIVED_KEY1_INDEX].key));
      trz_assert(bump_seed == bump_seed1);
    }

    trz_log("Test derived signers");
    {
      trz_assert(!accounts[DERIVED_KEY1_INDEX].is_signer);
      trz_assert(!accounts[DERIVED_KEY2_INDEX].is_signer);
      trz_assert(!accounts[DERIVED_KEY3_INDEX].is_signer);

      SolAccountMeta arguments[] = {
          {accounts[INVOKED_PROGRAM_INDEX].key, false, false},
          {accounts[DERIVED_KEY1_INDEX].key, true, true},
          {accounts[DERIVED_KEY2_INDEX].key, true, false},
          {accounts[DERIVED_KEY3_INDEX].key, false, false}};
      uint8_t data[] = {DERIVED_SIGNERS, bump_seed2, bump_seed3};
      const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                          arguments, TRZ_ARRAY_SIZE(arguments),
                                          data, TRZ_ARRAY_SIZE(data)};
      uint8_t seed1[] = {'Y', 'o', 'u', ' ', 'p', 'a', 's', 's',
                         ' ', 'b', 'u', 't', 't', 'e', 'r'};
      const SolSignerSeed seeds1[] = {{seed1, TRZ_ARRAY_SIZE(seed1)},
                                      {&bump_seed1, 1}};
      const SolSignerSeeds signers_seeds[] = {{seeds1, TRZ_ARRAY_SIZE(seeds1)}};
      trz_assert(SUCCESS == trz_invoke_signed(&instruction, accounts,
                                              TRZ_ARRAY_SIZE(accounts),
                                              signers_seeds,
                                              TRZ_ARRAY_SIZE(signers_seeds)));
    }

    trz_log("Test readonly with writable account");
    {
      SolAccountMeta arguments[] = {
          {accounts[INVOKED_ARGUMENT_INDEX].key, true, false}};
      uint8_t data[] = {VERIFY_WRITER};
      const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                          arguments, TRZ_ARRAY_SIZE(arguments),
                                          data, TRZ_ARRAY_SIZE(data)};

      trz_assert(SUCCESS ==
                 trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));
    }

    trz_log("Test nested invoke");
    {
      trz_assert(SUCCESS == do_nested_invokes(4, accounts, params.ka_num));
    }

    trz_log("Test privilege deescalation");
    {
      trz_assert(true == accounts[INVOKED_ARGUMENT_INDEX].is_signer);
      trz_assert(true == accounts[INVOKED_ARGUMENT_INDEX].is_writable);
      SolAccountMeta arguments[] = {
          {accounts[INVOKED_ARGUMENT_INDEX].key, false, false}};
      uint8_t data[] = {VERIFY_PRIVILEGE_DEESCALATION};
      const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                          arguments, TRZ_ARRAY_SIZE(arguments),
                                          data, TRZ_ARRAY_SIZE(data)};
      trz_assert(SUCCESS ==
                 trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));
    }

    trz_log("Verify data values are retained and updated");
    for (int i = 0; i < accounts[ARGUMENT_INDEX].data_len; i++) {
      trz_assert(accounts[ARGUMENT_INDEX].data[i] == i);
    }
    for (int i = 0; i < accounts[INVOKED_ARGUMENT_INDEX].data_len; i++) {
      trz_assert(accounts[INVOKED_ARGUMENT_INDEX].data[i] == i);
    }

    trz_log("Verify data write before ro cpi call");
    {
      for (int i = 0; i < accounts[ARGUMENT_INDEX].data_len; i++) {
        accounts[ARGUMENT_INDEX].data[i] = 0;
      }

      SolAccountMeta arguments[] = {
          {accounts[ARGUMENT_INDEX].key, false, false}};
      uint8_t data[] = {VERIFY_PRIVILEGE_DEESCALATION};
      const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                          arguments, TRZ_ARRAY_SIZE(arguments),
                                          data, TRZ_ARRAY_SIZE(data)};
      trz_assert(SUCCESS ==
                 trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));

      for (int i = 0; i < accounts[ARGUMENT_INDEX].data_len; i++) {
        trz_assert(accounts[ARGUMENT_INDEX].data[i] == 0);
      }
    }

    trz_log("Test that is_executable and rent_epoch are ignored");
    {
      accounts[INVOKED_ARGUMENT_INDEX].executable = true;
      accounts[INVOKED_ARGUMENT_INDEX].rent_epoch += 1;
      SolAccountMeta arguments[] = {
          {accounts[INVOKED_ARGUMENT_INDEX].key, true, false}};
      uint8_t data[] = {RETURN_OK};
      const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                          arguments, TRZ_ARRAY_SIZE(arguments),
                                          data, TRZ_ARRAY_SIZE(data)};

      trz_assert(SUCCESS ==
                 trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));
    }
    break;
  }
  case TEST_PRIVILEGE_ESCALATION_SIGNER: {
    trz_log("Test privilege escalation signer");
    SolAccountMeta arguments[] = {
        {accounts[DERIVED_KEY3_INDEX].key, false, false}};
    uint8_t data[] = {VERIFY_PRIVILEGE_ESCALATION};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    trz_assert(SUCCESS ==
               trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));

    // Signer privilege escalation will always fail the whole transaction
    instruction.accounts[0].is_signer = true;
    trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts));
    break;
  }
  case TEST_PRIVILEGE_ESCALATION_WRITABLE: {
    trz_log("Test privilege escalation writable");
    SolAccountMeta arguments[] = {
        {accounts[DERIVED_KEY3_INDEX].key, false, false}};
    uint8_t data[] = {VERIFY_PRIVILEGE_ESCALATION};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    trz_assert(SUCCESS ==
               trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));

    // Writable privilege escalation will always fail the whole transaction
    instruction.accounts[0].is_writable = true;
    trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts));
    break;
  }
  case TEST_PPROGRAM_NOT_OWNED_BY_LOADER: {
    trz_log("Test program not owned by loader");
    SolAccountMeta arguments[] = {
        {accounts[INVOKED_ARGUMENT_INDEX].key, false, false}};
    uint8_t data[] = {RETURN_OK};
    const SolInstruction instruction = {accounts[ARGUMENT_INDEX].key, arguments,
                                        TRZ_ARRAY_SIZE(arguments), data,
                                        TRZ_ARRAY_SIZE(data)};
    return trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts));
  }
  case TEST_PPROGRAM_NOT_EXECUTABLE: {
    trz_log("Test program not executable");
    SolAccountMeta arguments[] = {
        {accounts[INVOKED_ARGUMENT_INDEX].key, false, false}};
    uint8_t data[] = {RETURN_OK};
    const SolInstruction instruction = {accounts[UNEXECUTABLE_PROGRAM_INDEX].key, arguments,
                                        TRZ_ARRAY_SIZE(arguments), data,
                                        TRZ_ARRAY_SIZE(data)};
    return trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts));
  }
  case TEST_EMPTY_ACCOUNTS_SLICE: {
    trz_log("Empty accounts slice");

    SolAccountMeta arguments[] = {
        {accounts[INVOKED_ARGUMENT_INDEX].key, false, false}};
    uint8_t data[] = {};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};

    trz_assert(SUCCESS == trz_invoke(&instruction, 0, 0));
    break;
  }
  case TEST_CAP_SEEDS: {
    trz_log("Test cap seeds");
    SolAccountMeta arguments[] = {};
    uint8_t data[] = {};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    uint8_t seed[] = {"seed"};
    const SolSignerSeed seeds[] = {
        {seed, TRZ_ARRAY_SIZE(seed)}, {seed, TRZ_ARRAY_SIZE(seed)},
        {seed, TRZ_ARRAY_SIZE(seed)}, {seed, TRZ_ARRAY_SIZE(seed)},
        {seed, TRZ_ARRAY_SIZE(seed)}, {seed, TRZ_ARRAY_SIZE(seed)},
        {seed, TRZ_ARRAY_SIZE(seed)}, {seed, TRZ_ARRAY_SIZE(seed)},
        {seed, TRZ_ARRAY_SIZE(seed)}, {seed, TRZ_ARRAY_SIZE(seed)},
        {seed, TRZ_ARRAY_SIZE(seed)}, {seed, TRZ_ARRAY_SIZE(seed)},
        {seed, TRZ_ARRAY_SIZE(seed)}, {seed, TRZ_ARRAY_SIZE(seed)},
        {seed, TRZ_ARRAY_SIZE(seed)}, {seed, TRZ_ARRAY_SIZE(seed)},
        {seed, TRZ_ARRAY_SIZE(seed)},
    };
    const SolSignerSeeds signers_seeds[] = {{seeds, TRZ_ARRAY_SIZE(seeds)}};
    trz_assert(SUCCESS == trz_invoke_signed(
                              &instruction, accounts, TRZ_ARRAY_SIZE(accounts),
                              signers_seeds, TRZ_ARRAY_SIZE(signers_seeds)));
    break;
  }
  case TEST_CAP_SIGNERS: {
    trz_log("Test cap signers");
    SolAccountMeta arguments[] = {};
    uint8_t data[] = {};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    uint8_t seed[] = {"seed"};
    const SolSignerSeed seed1[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed2[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed3[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed4[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed5[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed6[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed7[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed8[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed9[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed10[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed11[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed12[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed13[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed14[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed15[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed16[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeed seed17[] = {{seed, TRZ_ARRAY_SIZE(seed)}};
    const SolSignerSeeds signers_seeds[] = {
        {seed1, TRZ_ARRAY_SIZE(seed1)},   {seed2, TRZ_ARRAY_SIZE(seed2)},
        {seed3, TRZ_ARRAY_SIZE(seed3)},   {seed4, TRZ_ARRAY_SIZE(seed4)},
        {seed5, TRZ_ARRAY_SIZE(seed5)},   {seed6, TRZ_ARRAY_SIZE(seed6)},
        {seed7, TRZ_ARRAY_SIZE(seed7)},   {seed8, TRZ_ARRAY_SIZE(seed8)},
        {seed9, TRZ_ARRAY_SIZE(seed9)},   {seed10, TRZ_ARRAY_SIZE(seed10)},
        {seed11, TRZ_ARRAY_SIZE(seed11)}, {seed12, TRZ_ARRAY_SIZE(seed12)},
        {seed13, TRZ_ARRAY_SIZE(seed13)}, {seed14, TRZ_ARRAY_SIZE(seed14)},
        {seed15, TRZ_ARRAY_SIZE(seed15)}, {seed16, TRZ_ARRAY_SIZE(seed16)},
        {seed17, TRZ_ARRAY_SIZE(seed17)}};
    trz_assert(SUCCESS == trz_invoke_signed(
                              &instruction, accounts, TRZ_ARRAY_SIZE(accounts),
                              signers_seeds, TRZ_ARRAY_SIZE(signers_seeds)));
    break;
  }
  case TEST_ALLOC_ACCESS_VIOLATION: {
    trz_log("Test resize violation");
    SolAccountMeta arguments[] = {
        {accounts[FROM_INDEX].key, true, true},
        {accounts[DERIVED_KEY1_INDEX].key, true, true}};
    uint8_t data[4 + 8 + 8 + 32];
    *(uint64_t *)(data + 4) = 42;
    *(uint64_t *)(data + 4 + 8) = MAX_PERMITTED_DATA_INCREASE;
    trz_memcpy(data + 4 + 8 + 8, params.program_id, SIZE_PUBKEY);
    const SolInstruction instruction = {accounts[SYSTEM_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    uint8_t seed1[] = {'Y', 'o', 'u', ' ', 'p', 'a', 's', 's',
                       ' ', 'b', 'u', 't', 't', 'e', 'r'};
    const SolSignerSeed seeds1[] = {{seed1, TRZ_ARRAY_SIZE(seed1)},
                                    {&bump_seed1, 1}};
    const SolSignerSeeds signers_seeds[] = {{seeds1, TRZ_ARRAY_SIZE(seeds1)}};

    SolAccountInfo derived_account = {
        .key = accounts[DERIVED_KEY1_INDEX].key,
        .lamports = accounts[DERIVED_KEY1_INDEX].lamports,
        .data_len = accounts[DERIVED_KEY1_INDEX].data_len,
        // Point to top edge of heap, attempt to allocate into unprivileged
        // memory
        .data = (uint8_t *)0x300007ff8,
        .owner = accounts[DERIVED_KEY1_INDEX].owner,
        .rent_epoch = accounts[DERIVED_KEY1_INDEX].rent_epoch,
        .is_signer = accounts[DERIVED_KEY1_INDEX].is_signer,
        .is_writable = accounts[DERIVED_KEY1_INDEX].is_writable,
        .executable = accounts[DERIVED_KEY1_INDEX].executable,
    };
    const SolAccountInfo invoke_accounts[] = {
        accounts[FROM_INDEX], accounts[SYSTEM_PROGRAM_INDEX], derived_account};
    trz_assert(SUCCESS ==
               trz_invoke_signed(&instruction,
                                 (const SolAccountInfo *)invoke_accounts, 3,
                                 signers_seeds, TRZ_ARRAY_SIZE(signers_seeds)));
    break;
  }
  case TEST_MAX_INSTRUCTION_DATA_LEN_EXCEEDED: {
    trz_log("Test max instruction data len exceeded");
    SolAccountMeta arguments[] = {};
    uint64_t data_len = MAX_CPI_INSTRUCTION_DATA_LEN + 1;
    uint8_t *data = trz_calloc(data_len, 1);
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, data_len};
    const SolSignerSeeds signers_seeds[] = {};
    trz_assert(SUCCESS == trz_invoke_signed(
                              &instruction, accounts, TRZ_ARRAY_SIZE(accounts),
                              signers_seeds, TRZ_ARRAY_SIZE(signers_seeds)));

    break;
  }
  case TEST_MAX_INSTRUCTION_ACCOUNTS_EXCEEDED: {
    trz_log("Test max instruction accounts exceeded");
    uint64_t accounts_len = MAX_CPI_INSTRUCTION_ACCOUNTS + 1;
    SolAccountMeta *arguments = trz_calloc(accounts_len, sizeof(SolAccountMeta));
    trz_assert(0 != arguments);
    uint8_t data[] = {};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, accounts_len, data,
                                        TRZ_ARRAY_SIZE(data)};
    const SolSignerSeeds signers_seeds[] = {};
    trz_assert(SUCCESS == trz_invoke_signed(
                              &instruction, accounts, TRZ_ARRAY_SIZE(accounts),
                              signers_seeds, TRZ_ARRAY_SIZE(signers_seeds)));

    break;
  }
  case TEST_MAX_ACCOUNT_INFOS_EXCEEDED: {
    trz_log("Test max account infos exceeded");
    SolAccountMeta arguments[] = {};
    uint64_t account_infos_len = MAX_CPI_ACCOUNT_INFOS + 1;
    SolAccountInfo *account_infos = trz_calloc(account_infos_len, sizeof(SolAccountInfo));
    trz_assert(0 != account_infos);
    uint8_t data[] = {};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    const SolSignerSeeds signers_seeds[] = {};
    trz_assert(SUCCESS == trz_invoke_signed(
                              &instruction, account_infos, account_infos_len,
                              signers_seeds, TRZ_ARRAY_SIZE(signers_seeds)));

    break;
  }
  case TEST_RETURN_ERROR: {
    trz_log("Test return error");
    SolAccountMeta arguments[] = {{accounts[ARGUMENT_INDEX].key, false, true}};
    uint8_t data[] = {RETURN_ERROR};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};

    trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts));
    break;
  }
  case TEST_PRIVILEGE_DEESCALATION_ESCALATION_SIGNER: {
    trz_log("Test privilege deescalation escalation signer");
    trz_assert(true == accounts[INVOKED_ARGUMENT_INDEX].is_signer);
    trz_assert(true == accounts[INVOKED_ARGUMENT_INDEX].is_writable);
    SolAccountMeta arguments[] = {
        {accounts[INVOKED_PROGRAM_INDEX].key, false, false},
        {accounts[INVOKED_ARGUMENT_INDEX].key, false, false}};
    uint8_t data[] = {VERIFY_PRIVILEGE_DEESCALATION_ESCALATION_SIGNER};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    trz_assert(SUCCESS ==
               trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));
    break;
  }
  case TEST_PRIVILEGE_DEESCALATION_ESCALATION_WRITABLE: {
    trz_log("Test privilege deescalation escalation writable");
    trz_assert(true == accounts[INVOKED_ARGUMENT_INDEX].is_signer);
    trz_assert(true == accounts[INVOKED_ARGUMENT_INDEX].is_writable);
    SolAccountMeta arguments[] = {
        {accounts[INVOKED_PROGRAM_INDEX].key, false, false},
        {accounts[INVOKED_ARGUMENT_INDEX].key, false, false}};
    uint8_t data[] = {VERIFY_PRIVILEGE_DEESCALATION_ESCALATION_WRITABLE};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    trz_assert(SUCCESS ==
               trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));
    break;
  }
  case TEST_WRITABLE_DEESCALATION_WRITABLE: {
    trz_log("Test writable deescalation");
    uint8_t buffer[10];
    for (int i = 0; i < 10; i++) {
      buffer[i] = accounts[INVOKED_ARGUMENT_INDEX].data[i];
    }
    SolAccountMeta arguments[] = {
        {accounts[INVOKED_ARGUMENT_INDEX].key, false, false}};
    uint8_t data[] = {WRITE_ACCOUNT, 10};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts));

    for (int i = 0; i < 10; i++) {
      trz_assert(buffer[i] == accounts[INVOKED_ARGUMENT_INDEX].data[i]);
    }
    break;
  }
  case TEST_NESTED_INVOKE_TOO_DEEP: {
    do_nested_invokes(5, accounts, params.ka_num);
    break;
  }
  case TEST_NESTED_INVOKE_SIMD_0268_OK: {
    do_nested_invokes(8, accounts, params.ka_num);
    break;
  }
  case TEST_NESTED_INVOKE_SIMD_0268_TOO_DEEP: {
    do_nested_invokes(9, accounts, params.ka_num);
    break;
  }
  case TEST_CALL_PRECOMPILE: {
    trz_log("Test calling precompile from cpi");
    SolAccountMeta arguments[] = {};
    uint8_t data[] = {};
    const SolInstruction instruction = {accounts[ED25519_PROGRAM_INDEX].key,
					arguments, TRZ_ARRAY_SIZE(arguments),
					data, TRZ_ARRAY_SIZE(data)};
    trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts));
    break;
  }
  case ADD_LAMPORTS: {
    *accounts[0].lamports += 1;
     break;
  }
  case TEST_RETURN_DATA_TOO_LARGE: {
    trz_log("Test setting return data too long");
    // The actual buffer doesn't matter, just pass null
    trz_set_return_data(NULL, 1027);
    break;
  }
  case TEST_DUPLICATE_PRIVILEGE_ESCALATION_SIGNER: {
    trz_log("Test duplicate privilege escalation signer");
    SolAccountMeta arguments[] = {
        {accounts[DERIVED_KEY3_INDEX].key, false, false},
        {accounts[DERIVED_KEY3_INDEX].key, false, false},
        {accounts[DERIVED_KEY3_INDEX].key, false, false}};
    uint8_t data[] = {VERIFY_PRIVILEGE_ESCALATION};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    trz_assert(SUCCESS ==
               trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));

    // Signer privilege escalation will always fail the whole transaction
    instruction.accounts[1].is_signer = true;
    trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts));
    break;
  }
  case TEST_DUPLICATE_PRIVILEGE_ESCALATION_WRITABLE: {
    trz_log("Test duplicate privilege escalation writable");
    SolAccountMeta arguments[] = {
        {accounts[DERIVED_KEY3_INDEX].key, false, false},
        {accounts[DERIVED_KEY3_INDEX].key, false, false},
        {accounts[DERIVED_KEY3_INDEX].key, false, false}};
    uint8_t data[] = {VERIFY_PRIVILEGE_ESCALATION};
    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    trz_assert(SUCCESS ==
               trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts)));

    // Writable privilege escalation will always fail the whole transaction
    instruction.accounts[1].is_writable = true;
    trz_invoke(&instruction, accounts, TRZ_ARRAY_SIZE(accounts));
    break;
  }
  case TEST_CPI_INVALID_KEY_POINTER:
  {
    trz_log("Test TEST_CPI_INVALID_KEY_POINTER");
    SolAccountMeta arguments[] = {
        {accounts[ARGUMENT_INDEX].key, false, false},
        {accounts[INVOKED_ARGUMENT_INDEX].key, false, false},
    };
    uint8_t data[] = {};
    SolPubkey key = *accounts[ARGUMENT_INDEX].key;
    accounts[ARGUMENT_INDEX].key = &key;

    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    trz_invoke(&instruction, accounts, 4);
    break;
  }
  case TEST_CPI_INVALID_LAMPORTS_POINTER:
  {
    trz_log("Test TEST_CPI_INVALID_LAMPORTS_POINTER");
    SolAccountMeta arguments[] = {
        {accounts[ARGUMENT_INDEX].key, false, false},
        {accounts[INVOKED_ARGUMENT_INDEX].key, false, false},
    };
    uint8_t data[] = {};
    uint64_t lamports = *accounts[ARGUMENT_INDEX].lamports;
    accounts[ARGUMENT_INDEX].lamports = &lamports;

    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    trz_invoke(&instruction, accounts, 4);
    break;
  }
  case TEST_CPI_INVALID_OWNER_POINTER:
  {
    trz_log("Test TEST_CPI_INVALID_OWNER_POINTER");
    SolAccountMeta arguments[] = {
        {accounts[ARGUMENT_INDEX].key, false, false},
        {accounts[INVOKED_ARGUMENT_INDEX].key, false, false},
    };
    uint8_t data[] = {};
    SolPubkey owner = *accounts[ARGUMENT_INDEX].owner;
    accounts[ARGUMENT_INDEX].owner = &owner;

    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    trz_invoke(&instruction, accounts, 4);
    break;
  }
  case TEST_CPI_INVALID_DATA_POINTER:
  {
    trz_log("Test TEST_CPI_INVALID_DATA_POINTER");
    SolAccountMeta arguments[] = {
        {accounts[ARGUMENT_INDEX].key, false, false},
        {accounts[INVOKED_ARGUMENT_INDEX].key, false, false},
    };
    uint8_t data[] = {};
    accounts[ARGUMENT_INDEX].data = data;

    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};
    trz_invoke(&instruction, accounts, 4);
    break;
  }
  case TEST_WRITE_ACCOUNT:
  {
    trz_log("Test TEST_WRITE_ACCOUNT");

    uint8_t target_account_index = params.data[1];
    uint64_t offset = *((uint64_t*)(params.data + 2));

    accounts[target_account_index].data[offset] = params.data[10];
    break;
  }
  case TEST_ACCOUNT_INFO_IN_ACCOUNT:
  {
    trz_log("Test TEST_ACCOUNT_INFO_IN_ACCOUNT");

    uint8_t data[] = { TEST_WRITE_ACCOUNT, 1,  1, 0, 0, 0, 0, 0, 0, 0,  1 };

    void *account_info_acc = accounts[1].data + 32;

    trz_memcpy(account_info_acc, accounts, sizeof(accounts[0]) * params.ka_num);

    SolAccountMeta arguments[] = {
        {accounts[INVOKED_PROGRAM_INDEX].key, false, false},
        {accounts[ARGUMENT_INDEX].key, true, false},
        {accounts[MINT_INDEX].key, false, false},
    };

    const SolInstruction instruction = {accounts[INVOKED_PROGRAM_INDEX].key,
                                        arguments, TRZ_ARRAY_SIZE(arguments),
                                        data, TRZ_ARRAY_SIZE(data)};

    trz_invoke(&instruction, account_info_acc, params.ka_num);
    break;
  }

  default:
    trz_panic();
  }

  return SUCCESS;
}
