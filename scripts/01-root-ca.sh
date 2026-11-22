#!/usr/bin/env bash
# Step 1: Create the Root CA (self-signed) and its initial CRL.
# Run from anywhere: bash scripts/01-root-ca.sh
# Passphrase for the root key is taken from ROOT_CA_PASS (demo default below).
set -euo pipefail

cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1   # stop Git Bash from mangling "/DC=..." style args

PASS="${ROOT_CA_PASS:-changeit-root}"
CONF=etc/root-ca.conf
CA=ca/root-ca
PROOF=proofs/part1

if [ -f ca/root-ca.crt ]; then
  echo "ca/root-ca.crt already exists - refusing to overwrite. Delete ca/root-ca* and crl/root-ca* to start over." >&2
  exit 1
fi

# 1.1 Create directories
mkdir -p "$CA/private" "$CA/db" crl certs "$PROOF"
chmod 700 "$CA/private"

# 1.2 Create database
: > "$CA/db/root-ca.db"
: > "$CA/db/root-ca.db.attr"
echo 01 > "$CA/db/root-ca.crt.srl"
echo 01 > "$CA/db/root-ca.crl.srl"

# 1.3 Create CA request (generates the 4096-bit RSA private key)
openssl req -new \
  -config "$CONF" \
  -out "$CA.csr" \
  -keyout "$CA/private/root-ca.key" \
  -passout "pass:$PASS"

# 1.4 Create CA certificate (self-signed, root_ca_ext)
openssl ca -selfsign -batch \
  -config "$CONF" \
  -in "$CA.csr" \
  -out ca/root-ca.crt \
  -extensions root_ca_ext \
  -passin "pass:$PASS"

# 1.5 Create initial (empty) CRL
openssl ca -gencrl \
  -config "$CONF" \
  -out crl/root-ca.crl \
  -passin "pass:$PASS"

# 1.6 DER copies for publishing (Windows/browsers like .cer/.crl in DER)
openssl x509 -in ca/root-ca.crt -outform der -out ca/root-ca.cer
openssl crl  -in crl/root-ca.crl -outform der -out crl/root-ca.der.crl

# 1.7 Save verification output
openssl x509 -in ca/root-ca.crt -noout -text           > "$PROOF/root-ca-cert.txt"
openssl x509 -in ca/root-ca.crt -noout -subject -issuer -serial -dates \
                                                        > "$PROOF/root-ca-summary.txt"
openssl x509 -in ca/root-ca.crt -noout -fingerprint -sha256 >> "$PROOF/root-ca-summary.txt"
openssl verify -CAfile ca/root-ca.crt ca/root-ca.crt    > "$PROOF/root-ca-verify.txt"
openssl crl -in crl/root-ca.crl -noout -text            > "$PROOF/root-ca-crl.txt"
openssl rsa -in "$CA/private/root-ca.key" -passin "pass:$PASS" -noout -check \
                                                        > "$PROOF/root-ca-key-check.txt"
ls -l ca ca/root-ca ca/root-ca/db crl                   > "$PROOF/root-ca-files.txt"

echo
echo "Root CA created:"
cat "$PROOF/root-ca-summary.txt"
cat "$PROOF/root-ca-verify.txt"
