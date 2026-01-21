# populate this on the stable branch
tplTokenCliVersion=

maybeSplTokenCliVersionArg=
if [[ -n "$tplTokenCliVersion" ]]; then
    # shellcheck disable=SC2034
    maybeSplTokenCliVersionArg="--version $tplTokenCliVersion"
fi
