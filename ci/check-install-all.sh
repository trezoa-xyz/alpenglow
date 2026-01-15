source scripts/tpl-token-cli-version.sh
if [[ -z $splTokenCliVersion ]]; then
    echo "On the stable channel, splTokenCliVersion must be set in scripts/tpl-token-cli-version.sh"
    exit 1
fi
