#!/bin/sh
set -eu

# This one-shot Compose service runs only after the disposable DC is healthy.
# Passwords arrive through Compose environment variables; no working secret is
# stored in this repository.
SAMBA_URL="ldap://samba-ad"
ADMIN_USER="NETRAZE\\Administrator"

if ! samba-tool spn list svc_http \
    -H "$SAMBA_URL" \
    --username="$ADMIN_USER" \
    --password="$NETRAZE_SAMBA_AD_ADMIN_PASSWORD" \
    --use-kerberos=off 2>/dev/null | grep -Fq "HTTP/web.netraze.test"; then
    samba-tool spn add "HTTP/web.netraze.test" svc_http \
        -H "$SAMBA_URL" \
        --username="$ADMIN_USER" \
        --password="$NETRAZE_SAMBA_AD_ADMIN_PASSWORD" \
        --use-kerberos=off
fi

# UF_NORMAL_ACCOUNT (0x200) | UF_DONT_REQUIRE_PREAUTH (0x400000).
# `replace` makes the fixture idempotent when the disposable volume is reused.
ASREP_DN="$(samba-tool user show asrep \
    --attributes=distinguishedName \
    -H "$SAMBA_URL" \
    --username="$ADMIN_USER" \
    --password="$NETRAZE_SAMBA_AD_ADMIN_PASSWORD" \
    --use-kerberos=off 2>/dev/null | sed -n 's/^dn: //p')"
if [ -z "$ASREP_DN" ]; then
    echo "could not resolve the asrep fixture distinguished name" >&2
    exit 1
fi

cat <<EOF | ldbmodify \
    -H "$SAMBA_URL" \
    --user="$ADMIN_USER" \
    --password="$NETRAZE_SAMBA_AD_ADMIN_PASSWORD" \
    --use-kerberos=off
dn: $ASREP_DN
changetype: modify
replace: userAccountControl
userAccountControl: 4194816
EOF

samba-tool user show asrep \
    --attributes=userAccountControl \
    -H "$SAMBA_URL" \
    --username="$ADMIN_USER" \
    --password="$NETRAZE_SAMBA_AD_ADMIN_PASSWORD" \
    --use-kerberos=off 2>/dev/null | grep -Fq "userAccountControl: 4194816"
