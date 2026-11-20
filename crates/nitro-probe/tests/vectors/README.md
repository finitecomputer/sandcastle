# CMS test vectors (TEST ONLY)

Made once with OpenSSL 3.5.8 on the spike's parent (2026-11-20), so the
probe's CMS walk is held to another implementation's output. The key is a
throwaway made for these files alone; it protects nothing.

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-only-key.pem
openssl req -new -x509 -key test-only-key.pem -subj "/CN=nitro-probe test vectors, TEST ONLY" -days 3650 -out test-only-cert.pem
head -c 32 /dev/urandom > plaintext.bin
K="-keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha256"
openssl cms -encrypt -binary -aes256 -in plaintext.bin -recip test-only-cert.pem $K -outform DER -out sealed.der
openssl cms -encrypt -binary -aes256 -stream -in plaintext.bin -recip test-only-cert.pem $K -outform DER -out sealed-streamed.ber
```

`sealed.der` is definite-length DER; `sealed-streamed.ber` is BER with
indefinite lengths (it starts `30 80`). Both reopen with `openssl cms
-decrypt` to `plaintext.bin`. The envelope's shape (RSAES-OAEP with
SHA-256 and MGF1 SHA-256, AES-256-CBC content) is what KMS's
`CiphertextForRecipient` uses for `RSAES_OAEP_SHA_256`.
