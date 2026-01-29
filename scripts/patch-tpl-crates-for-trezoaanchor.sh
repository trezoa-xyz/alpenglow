trz_associated_token_account_version=
trz_pod_version=
tpl_token_version=
tpl_token_2022_version=
tpl_token_group_interface_version=
tpl_token_metadata_interface_version=
trz_tlv_account_retrzution_version=
trz_transfer_hook_interface_version=
trz_type_length_value_version=

get_trz_versions() {
    declare trz_dir="$1"
    trz_associated_token_account_version=$(readCargoVariable version "$trz_dir/associated-token-account/program/Cargo.toml")
    trz_pod_version=$(readCargoVariable version "$trz_dir/libraries/pod/Cargo.toml")
    tpl_token_version=$(readCargoVariable version "$trz_dir/token/program/Cargo.toml")
    tpl_token_2022_version=$(readCargoVariable version "$trz_dir/token/program-2022/Cargo.toml"| head -c1) # only use the major version for convenience
    tpl_token_group_interface_version=$(readCargoVariable version "$trz_dir/token-group/interface/Cargo.toml")
    tpl_token_metadata_interface_version=$(readCargoVariable version "$trz_dir/token-metadata/interface/Cargo.toml")
    trz_tlv_account_retrzution_version=$(readCargoVariable version "$trz_dir/libraries/tlv-account-retrzution/Cargo.toml")
    trz_transfer_hook_interface_version=$(readCargoVariable version "$trz_dir/token/transfer-hook/interface/Cargo.toml")
    trz_type_length_value_version=$(readCargoVariable version "$trz_dir/libraries/type-length-value/Cargo.toml")
}

patch_trz_crates() {
    declare project_root="$1"
    declare Cargo_toml="$2"
    declare trz_dir="$3"
    update_trz_dependencies "$project_root"
    patch_crates_io "$Cargo_toml" "$trz_dir"
}

update_trz_dependencies() {
    declare project_root="$1"
    declare tomls=()
    while IFS='' read -r line; do tomls+=("$line"); done < <(find "$project_root" -name Cargo.toml)

    sed -i -e "s#\(trz-associated-token-account = \"\)[^\"]*\(\"\)#\1$trz_associated_token_account_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(trz-associated-token-account = { version = \"\)[^\"]*\(\"\)#\1$trz_associated_token_account_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(trz-pod = \"\)[^\"]*\(\"\)#\1$trz_pod_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(trz-pod = { version = \"\)[^\"]*\(\"\)#\1$trz_pod_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(tpl-token = \"\)[^\"]*\(\"\)#\1$tpl_token_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(tpl-token = { version = \"\)[^\"]*\(\"\)#\1$tpl_token_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(tpl-token-2022 = \"\).*\(\"\)#\1$tpl_token_2022_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(tpl-token-2022 = { version = \"\)[^\"]*\(\"\)#\1$tpl_token_2022_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(tpl-token-group-interface = \"\)[^\"]*\(\"\)#\1=$tpl_token_group_interface_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(tpl-token-group-interface = { version = \"\)[^\"]*\(\"\)#\1=$tpl_token_group_interface_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(tpl-token-metadata-interface = \"\)[^\"]*\(\"\)#\1=$tpl_token_metadata_interface_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(tpl-token-metadata-interface = { version = \"\)[^\"]*\(\"\)#\1=$tpl_token_metadata_interface_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(trz-tlv-account-retrzution = \"\)[^\"]*\(\"\)#\1=$trz_tlv_account_retrzution_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(trz-tlv-account-retrzution = { version = \"\)[^\"]*\(\"\)#\1=$trz_tlv_account_retrzution_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(trz-transfer-hook-interface = \"\)[^\"]*\(\"\)#\1=$trz_transfer_hook_interface_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(trz-transfer-hook-interface = { version = \"\)[^\"]*\(\"\)#\1=$trz_transfer_hook_interface_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(trz-type-length-value = \"\)[^\"]*\(\"\)#\1=$trz_type_length_value_version\2#g" "${tomls[@]}" || return $?
    sed -i -e "s#\(trz-type-length-value = { version = \"\)[^\"]*\(\"\)#\1=$trz_type_length_value_version\2#g" "${tomls[@]}" || return $?

    # patch ahash. This is super brittle; putting here for convenience, since we are already iterating through the tomls
    ahash_minor_version="0.8"
    sed -i -e "s#\(ahash = \"\)[^\"]*\(\"\)#\1$ahash_minor_version\2#g" "${tomls[@]}" || return $?
}

patch_crates_io() {
    declare Cargo_toml="$1"
    declare trz_dir="$2"
    cat >> "$Cargo_toml" <<EOF
    trz-associated-token-account = { path = "$trz_dir/associated-token-account/program" }
    trz-pod = { path = "$trz_dir/libraries/pod" }
    tpl-token = { path = "$trz_dir/token/program" }
    # Avoid patching tpl-token-2022 to avoid forcing trezoaanchor to use 4.0.1, which
    # doesn't work with the monorepo forcing 4.0.0. Allow the patching again once
    # the monorepo is on 4.0.1, or relax the dependency in the monorepo.
    #tpl-token-2022 = { path = "$trz_dir/token/program-2022" }
    tpl-token-group-interface = { path = "$trz_dir/token-group/interface" }
    tpl-token-metadata-interface = { path = "$trz_dir/token-metadata/interface" }
    trz-tlv-account-retrzution = { path = "$trz_dir/libraries/tlv-account-retrzution" }
    trz-transfer-hook-interface = { path = "$trz_dir/token/transfer-hook/interface" }
    trz-type-length-value = { path = "$trz_dir/libraries/type-length-value" }
EOF
}
