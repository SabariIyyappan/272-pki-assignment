# HW #7 – PKI: Root CA → Signing CA → TLS Certificate → Tomcat HTTPS

A two-tier PKI built with OpenSSL following the
[Simple PKI tutorial](https://pki-tutorial.readthedocs.io/en/latest/simple/),
with the resulting TLS server certificate installed in Apache Tomcat
([SSL How-To](https://tomcat.apache.org/tomcat-7.0-doc/ssl-howto.html)).

```
Simple Root CA  (self-signed, offline, 10 yrs)
   └── Simple Signing CA  (pathlen:0, issues end-entity certs)
          └── TLS server certificate  (localhost)  →  Tomcat :8443
```

## Layout

```
etc/        OpenSSL configuration files (root-ca.conf, signing-ca.conf, server.conf)
scripts/    Numbered build scripts, run in order
ca/         CA certificates (*.crt PEM, *.cer DER), CA databases; private/ is git-ignored
crl/        Certificate revocation lists
certs/      Issued end-entity certificates
proofs/     Command output captured by the scripts
```

## Build

Requires OpenSSL 1.1+/3.x (Git Bash on Windows works).

```bash
bash scripts/01-root-ca.sh        # Root CA + root CRL
bash scripts/02-signing-ca.sh     # Signing CA signed by Root CA
bash scripts/03-tls-cert.sh       # TLS server certificate + PKCS#12 for Tomcat
bash scripts/04-tomcat.sh         # Tomcat HTTPS on :8443 + verification
```

Key passphrases are read from environment variables (e.g. `ROOT_CA_PASS`); demo defaults are
used if unset. Private keys are never committed.

## Verify the Root CA

```bash
openssl x509 -in ca/root-ca.crt -noout -text
openssl verify -CAfile ca/root-ca.crt ca/root-ca.crt
openssl crl -in crl/root-ca.crl -noout -text
```
