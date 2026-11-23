# Part 3 – TLS Server Certificate (Member 3: Samhitha Banda)

## Goal
Create a private key and certificate signing request (CSR) for the web server, with a Subject
Alternative Name (SAN) for `localhost`. Have the Simple Signing CA issue the TLS certificate,
then verify the full chain: TLS cert → Signing CA → Root CA.

## Inputs (from Part 2, branch `fallback-root`)
| File | Purpose |
|---|---|
| `ca/signing-ca.crt` | Signing CA certificate (issuer of the TLS cert) |
| `ca/signing-ca/private/signing-ca.key` | Signing CA private key, shared privately and git-ignored |
| `ca/ca-chain.crt` | Signing CA + Root CA bundle |
| `etc/signing-ca.conf` | Signing CA config: `server_ext` profile, `copy_extensions = copy` |

The Signing CA had not issued anything yet. So its database was started fresh: an empty
`signing-ca.db`, certificate serial `01`, and CRL number `02` (CRL 01 was already published by Member 2).

## Configuration – `etc/server.conf`
- 2048-bit RSA key, SHA-256, encrypted private key
- DN: `DC=org, DC=simple, O=Simple Inc, OU=Simple Web Server, CN=localhost`
  (O must match the Signing CA because of `match_pol`)
- Requested extensions: `keyUsage = digitalSignature,keyEncipherment`,
  `extendedKeyUsage = serverAuth,clientAuth`, and
  **`subjectAltName = DNS:localhost, IP:127.0.0.1`**

Modern browsers ignore the CN and check only the SAN. That's why the SAN is required for
`https://localhost` to be trusted.

## Commands (`scripts/03-tls-cert.sh`)

```bash
# 3.1 Signing CA database (fresh, no certs issued yet)
mkdir -p ca/signing-ca/private ca/signing-ca/db certs
chmod 700 ca/signing-ca/private
cp /dev/null ca/signing-ca/db/signing-ca.db
cp /dev/null ca/signing-ca/db/signing-ca.db.attr
echo 01 > ca/signing-ca/db/signing-ca.crt.srl
echo 02 > ca/signing-ca/db/signing-ca.crl.srl

# 3.2 Server key + CSR with SAN
openssl req -new -config etc/server.conf \
  -out certs/localhost.csr -keyout certs/localhost.key

# 3.3 Issue the TLS certificate with the Signing CA
openssl ca -config etc/signing-ca.conf \
  -in certs/localhost.csr -out certs/localhost.crt -extensions server_ext

# 3.4 Bundles for Tomcat (Member 4)
cat certs/localhost.crt ca/ca-chain.crt > certs/localhost-fullchain.pem
openssl pkcs12 -export -name localhost \
  -inkey certs/localhost.key -in certs/localhost.crt \
  -certfile ca/ca-chain.crt -out certs/localhost.p12

# 3.5 Verify
openssl x509 -in certs/localhost.crt -noout -text
openssl verify -CAfile ca/root-ca.crt -untrusted ca/signing-ca.crt certs/localhost.crt
openssl verify -purpose sslserver -CAfile ca/ca-chain.crt certs/localhost.crt
```

## Results
**Issued certificate** (`proofs/part3/tls-cert-summary.txt`)
```
subject= /DC=org/DC=simple/O=Simple Inc/OU=Simple Web Server/CN=localhost
issuer=  /DC=org/DC=simple/O=Simple Inc/OU=Simple Signing CA/CN=Simple Signing CA
serial=01
notBefore=Nov 23 05:04:26 2026 GMT
notAfter=Nov 22 05:04:26 2028 GMT   (730 days)
```

**Extensions** (`proofs/part3/tls-cert-extensions.txt`)
```
X509v3 Key Usage: critical        Digital Signature, Key Encipherment
X509v3 Basic Constraints:         CA:FALSE
X509v3 Extended Key Usage:        TLS Web Server Authentication, TLS Web Client Authentication
X509v3 Subject Alternative Name:  DNS:localhost, IP Address:127.0.0.1
```

**Chain verification** (`proofs/part3/tls-chain-verify.txt`)
```
$ openssl verify -CAfile ca/root-ca.crt -untrusted ca/signing-ca.crt certs/localhost.crt
certs/localhost.crt: OK
$ openssl verify -purpose sslserver -CAfile ca/ca-chain.crt certs/localhost.crt
certs/localhost.crt: OK
```

**Key/cert match** (`proofs/part3/tls-key-match.txt`): the key and cert moduli have the same SHA-256 hash.

**TLS handshake test** (`proofs/part3/tls-handshake-test.txt`): before handing off to Tomcat,
the cert, key and chain were served by a temporary local HTTPS server. Only the Root CA was trusted on the client.
```
depth=2 ... CN = Simple Root CA      verify return:1
depth=1 ... CN = Simple Signing CA   verify return:1
depth=0 ... CN = localhost           verify return:1
Protocol: TLSv1.3
$ curl --cacert ca/root-ca.crt https://localhost:8444/   ->  HTTP 200, ssl_verify_result=0
```

## Hand-off to Member 4 (Tomcat)
| File | In git? | Use |
|---|---|---|
| `certs/localhost.crt` | yes | server certificate (PEM) |
| `certs/localhost-fullchain.pem` | yes | cert + Signing CA + Root CA |
| `ca/ca-chain.crt` | yes | CA chain for Tomcat `certificateChainFile` |
| `certs/localhost.key` | **no** (shared privately) | server private key |
| `certs/localhost.p12` | **no** (shared privately) | PKCS#12 keystore (alias `localhost`) for Tomcat |

Tomcat connector (PKCS#12 option):
```xml
<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
           SSLEnabled="true" scheme="https" secure="true">
  <SSLHostConfig>
    <Certificate certificateKeystoreFile="conf/localhost.p12"
                 certificateKeystoreType="PKCS12"
                 certificateKeystorePassword="changeit" type="RSA"/>
  </SSLHostConfig>
</Connector>
```
To make browsers trust it, import `ca/root-ca.crt` as a trusted root (macOS Keychain, Windows cert
store, or Firefox Settings → Certificates).

## Security notes
- The private keys (`*.key`, `*.p12`, `ca/**/private/`) are git-ignored and are never pushed.
- The server key and PKCS#12 keystore use a demo passphrase (`SERVER_PASS`, default `changeit`).
  The Signing CA passphrase is read from `SIGNING_CA_PASS`.
