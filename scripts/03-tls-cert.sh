#!/usr/bin/env bash
# Step 3 (Member 3): Create the TLS server key + CSR (SAN = localhost),
# issue the TLS certificate with the Signing CA, and verify the full chain.
# Run from anywhere: bash scripts/03-tls-cert.sh
#
# Needs (from Member 2, on branch fallback-root):
#   ca/signing-ca.crt, ca/ca-chain.crt, ca/root-ca.crt, etc/signing-ca.conf
#   ca/signing-ca/private/signing-ca.key   (shared privately, never committed)
#
# Passphrases:
#   SIGNING_CA_PASS  Signing CA key passphrase (set by Member 2)
#   SERVER_PASS      passphrase for the server key and the PKCS#12 keystore used by Tomcat
set -euo pipefail

cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1   # stop Git Bash from mangling "/DC=..." style args

CA_PASS="${SIGNING_CA_PASS:?set SIGNING_CA_PASS to the Signing CA key passphrase (shared privately by Member 2)}"
SERVER_PASS="${SERVER_PASS:-changeit}"
CA=ca/signing-ca
NAME=localhost
PROOF=proofs/part3

for f in ca/signing-ca.crt ca/ca-chain.crt ca/root-ca.crt "$CA/private/signing-ca.key"; do
  [ -f "$f" ] || { echo "Missing $f (get Member 2's outputs / Signing CA key first)" >&2; exit 1; }
done
if [ -f "certs/$NAME.crt" ]; then
  echo "certs/$NAME.crt already exists - refusing to overwrite. Delete certs/$NAME.* to start over." >&2
  exit 1
fi

# 3.1 Signing CA database (not in git; create it if this machine doesn't have it)
mkdir -p "$CA/db" certs "$PROOF"
[ -f "$CA/db/signing-ca.db" ]      || : > "$CA/db/signing-ca.db"
[ -f "$CA/db/signing-ca.db.attr" ] || : > "$CA/db/signing-ca.db.attr"
[ -f "$CA/db/signing-ca.crt.srl" ] || echo 01 > "$CA/db/signing-ca.crt.srl"
[ -f "$CA/db/signing-ca.crl.srl" ] || echo 02 > "$CA/db/signing-ca.crl.srl"

# 3.2 Create TLS server request (generates the 2048-bit RSA key, SAN from etc/server.conf)
openssl req -new \
  -config etc/server.conf \
  -out "certs/$NAME.csr" \
  -keyout "certs/$NAME.key" \
  -passout "pass:$SERVER_PASS"
chmod 600 "certs/$NAME.key"

# 3.3 Issue TLS server certificate with the Signing CA (server_ext, SAN copied from CSR)
openssl ca -batch \
  -config etc/signing-ca.conf \
  -in "certs/$NAME.csr" \
  -out "certs/$NAME.crt" \
  -extensions server_ext \
  -passin "pass:$CA_PASS"

# 3.4 Bundles for the web server (Member 4)
#   certs/localhost-fullchain.pem : server cert + Signing CA + Root CA (PEM)
#   certs/localhost.p12           : key + cert + chain, PKCS#12 keystore for Tomcat (not committed)
cat "certs/$NAME.crt" ca/ca-chain.crt > "certs/$NAME-fullchain.pem"
openssl x509 -in "certs/$NAME.crt" -outform der -out "certs/$NAME.cer"
openssl pkcs12 -export \
  -name "$NAME" \
  -inkey "certs/$NAME.key" -passin "pass:$SERVER_PASS" \
  -in "certs/$NAME.crt" \
  -certfile ca/ca-chain.crt \
  -out "certs/$NAME.p12" \
  -passout "pass:$SERVER_PASS"

# 3.5 Save verification output
openssl req  -in "certs/$NAME.csr" -noout -text -verify  > "$PROOF/tls-csr.txt" 2>&1
openssl x509 -in "certs/$NAME.crt" -noout -text          > "$PROOF/tls-cert.txt"
openssl x509 -in "certs/$NAME.crt" -noout -subject -issuer -serial -dates \
                                                         > "$PROOF/tls-cert-summary.txt"
openssl x509 -in "certs/$NAME.crt" -noout -fingerprint -sha256 >> "$PROOF/tls-cert-summary.txt"
openssl x509 -in "certs/$NAME.crt" -noout -text \
  | grep -A1 -E "Subject Alternative Name|Basic Constraints|Key Usage|Extended Key Usage" \
                                                         > "$PROOF/tls-cert-extensions.txt"
{
  echo "\$ openssl verify -CAfile ca/root-ca.crt -untrusted ca/signing-ca.crt certs/$NAME.crt"
  openssl verify -CAfile ca/root-ca.crt -untrusted ca/signing-ca.crt "certs/$NAME.crt"
  echo
  echo "\$ openssl verify -CAfile ca/ca-chain.crt certs/$NAME.crt"
  openssl verify -CAfile ca/ca-chain.crt "certs/$NAME.crt"
  echo
  echo "\$ openssl verify -purpose sslserver -CAfile ca/ca-chain.crt certs/$NAME.crt"
  openssl verify -purpose sslserver -CAfile ca/ca-chain.crt "certs/$NAME.crt"
} > "$PROOF/tls-chain-verify.txt" 2>&1
{
  echo "key modulus  (sha256): $(openssl rsa  -in "certs/$NAME.key" -passin "pass:$SERVER_PASS" -noout -modulus | openssl sha256 | awk '{print $NF}')"
  echo "cert modulus (sha256): $(openssl x509 -in "certs/$NAME.crt" -noout -modulus | openssl sha256 | awk '{print $NF}')"
} > "$PROOF/tls-key-match.txt"
openssl pkcs12 -in "certs/$NAME.p12" -passin "pass:$SERVER_PASS" -nokeys -info 2>&1 \
  | grep -E "^(subject|issuer)=|MAC|PKCS7" > "$PROOF/tls-p12-contents.txt" || true
cp "$CA/db/signing-ca.db" "$PROOF/signing-ca-db.txt"
ls -l certs                                              > "$PROOF/tls-files.txt"

echo
echo "TLS server certificate issued:"
cat "$PROOF/tls-cert-summary.txt"
cat "$PROOF/tls-cert-extensions.txt"
cat "$PROOF/tls-chain-verify.txt"
cat "$PROOF/tls-key-match.txt"
