source scripts/tpl-token-cli-version.sh
if [[ -z $tplTokenCliVersion ]]; then
    echo "On the stable channel, tplTokenCliVersion must be set in scripts/tpl-token-cli-version.sh"
    exit 1
fi
