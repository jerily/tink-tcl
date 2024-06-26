# tink-tcl

Tcl bindings for [Tink](https://github.com/tink-crypto/tink-cc), a multi-language, cross-platform library that provides cryptographic APIs that are secure, easy to use correctly, and hard(er) to misuse.

## Clone the repository
```bash
git clone https://github.com/jerily/tink-tcl.git
cd tink-tcl
export TINK_TCL_DIR=`pwd`
```

## Install dependencies

A compatible C++ compiler supporting at least C++14 is required.

### Abseil

```bash
wget https://github.com/abseil/abseil-cpp/archive/refs/tags/20230125.0.tar.gz
tar -xzf 20230125.0.tar.gz
cd abseil-cpp-20230125.0
mkdir build
cd build
cmake .. \
  -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_STANDARD=14 \
  -DCMAKE_INSTALL_PREFIX=/usr/local
make
make install
```

### protobuf
```bash
wget https://github.com/protocolbuffers/protobuf/archive/v21.9.zip
unzip v21.9.zip -d .
cd protobuf-21.9
mkdir build
cd build
cmake .. \
-DBUILD_SHARED_LIBS=ON \
-DCMAKE_BUILD_TYPE=Release \
-Dprotobuf_BUILD_TESTS=OFF \
-DCMAKE_POSITION_INDEPENDENT_CODE=ON \
-Dprotobuf_BUILD_SHARED_LIBS=ON -DCMAKE_CXX_FLAGS="-fPIC" \
-DCMAKE_INSTALL_PREFIX=/usr/local
make
make install
```

### tink
```
wget https://github.com/tink-crypto/tink-cc/archive/refs/tags/v2.1.1.tar.gz
tar -xzf v2.1.1.tar.gz
cd tink-cc-2.1.1
patch -p1 < ${TINK_TCL_DIR}/tink-cc-2.1.1.diff
mkdir build
cd build
cmake .. \
  -DTINK_BUILD_SHARED_LIB=ON \
  -DTINK_USE_INSTALLED_ABSEIL=ON \
  -DTINK_USE_SYSTEM_OPENSSL=OFF \
  -DTINK_USE_INSTALLED_PROTOBUF=ON \
  -DTINK_USE_INSTALLED_RAPIDJSON=OFF \
  -DTINK_BUILD_TESTS=OFF \
  -DCMAKE_SKIP_RPATH=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr/local
make
make install
```

## Install module for TCL
```bash
cd ${TINK_TCL_DIR}
mkdir build
cd build
# change "TCL_LIBRARY_DIR" and "TCL_INCLUDE_DIR" to the correct paths
# or skip them to install in /usr/local
cmake .. \
  -DTCL_LIBRARY_DIR=/usr/local/lib \
  -DTCL_INCLUDE_DIR=/usr/local/include
make
make install
```

## TCL Commands

### Keyset

* **::tink::register_keyset** *keyset*
    - Registers the given keyset and returns a handle.
  ```tcl
    set keyset {{
      "key": [{
          "keyData": {
              "keyMaterialType":
                  "SYMMETRIC",
              "typeUrl":
                  "type.googleapis.com/google.crypto.tink.AesGcmKey",
              "value":
                  "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "keyId": 294406504,
          "outputPrefixType": "TINK",
          "status": "ENABLED"
      }],
      "primaryKeyId": 294406504
    }}

    set keyset_handle [::tink::register_keyset $keyset]
  ```
* **::tink::unregister_keyset** *keyset_handle*
    - Unregisters the given keyset handle.
  ```tcl
    ::tink::unregister_keyset $keyset_handle
  ```
* **::tink::create_public_keyset** *private_keyset*
    - Creates a new public keyset from the given private keyset and returns it.
  ```tcl
    set public_keyset [::tink::create_public_keyset $private_keyset]
  ```

### Authenticated Encryption with Associated Data (AEAD)

* **::tink::aead::encrypt** *keyset_handle* *plaintext* *?associated_data?*
    - Encrypts the given plaintext with the given keyset handle and returns the resulting ciphertext.
  ```tcl
  set encrypted [::tink::aead::encrypt $keyset_handle "someone@example.com" "email"]
  ```
* **::tink::aead::decrypt** *keyset_handle* *ciphertext* *?associated_data?*
    - Decrypts the given ciphertext with the given keyset handle and returns the resulting plaintext.
  ```tcl
  set decrypted [::tink::aead::decrypt $keyset_handle $encrypted "email"]
  ```
* **::tink::aead::create_keyset** *aead_key_template*
    - Creates a new keyset with one key using the given key template. Supported key templates are the following:
      - AES128_EAX
      - AES256_EAX
      - AES128_GCM
      - AES128_GCM_NO_PREFIX
      - AES256_GCM
      - AES256_GCM_NO_PREFIX
      - AES128_GCM_SIV
      - AES256_GCM_SIV
      - AES128_CTR_HMAC_SHA256
      - AES256_CTR_HMAC_SHA256
      - XCHACHA20_POLY1305
  ```tcl
  set keyset [::tink::aead::create_keyset "AES256_GCM"]
  ```

### Message Authentication Codes (MAC)

* **::tink::mac::compute** *keyset_handle* *content*
    - Computes the MAC for the given data with the given keyset handle and returns the resulting MAC.
  ```tcl
  set tag [::tink::mac::compute $hmac_keyset_handle "hello world"]
  ```
* **::tink::mac::verify** *keyset_handle* *tag* *content*
    - Verifies the given MAC against the given data with the given keyset handle and returns the resulting boolean.
  ```tcl
  set verified [::tink::mac::verify $hmac_keyset_handle $tag "hello world"]
  ```
* **::tink::mac::create_keyset** *mac_key_template*
    - Creates a new keyset with one key using the given key template. Supported key templates are the following:
        - HMAC_SHA256_128BITTAG
        - HMAC_SHA256
        - HMAC_SHA512_256BITTAG
        - HMAC_SHA512
        - AES_CMAC
  ```tcl
  set keyset [::tink::mac::create_keyset "HMAC_SHA256"]
  ```
  
### Hybrid Encryption

* **::tink::hybrid::encrypt** *keyset_handle* *plaintext* *?context_info?*
    - Encrypts the given plaintext with the given keyset handle and returns the resulting ciphertext.
  ```tcl
  set encrypted [::tink::hybrid::encrypt $hybrid_test_public_keyset_handle $plaintext $context_info]
  ```
* **::tink::hybrid::decrypt** *keyset_handle* *ciphertext* *?context_info?*
    - Decrypts the given ciphertext with the given keyset handle and returns the resulting plaintext.
  ```tcl
  set decrypted [::tink::hybrid::decrypt $hybrid_test_private_keyset_handle $encrypted $context_info]
  ```
* **::tink::hybrid::create_private_keyset** *hybrid_key_template*
    - Creates a new keyset with one key using the given key template. Supported key templates are the following:
        - ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
        - ECIES_P256_HKDF_HMAC_SHA512_AES128_GCM
        - ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_NO_PREFIX
        - ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256
        - ECIES_P256_HKDF_HMAC_SHA512_AES128_CTR_HMAC_SHA256
        - ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM
        - ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256
        - ECIES_X25519_HKDF_HMAC_SHA256_AES128_GCM
        - ECIES_X25519_HKDF_HMAC_SHA256_AES256_GCM
        - ECIES_X25519_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256
        - ECIES_X25519_HKDF_HMAC_SHA256_XCHACHA20_POLY1305
        - ECIES_X25519_HKDF_HMAC_SHA256_DETERMINISTIC_AES_SIV
        - HPKE_X25519_HKDF_SHA256_AES128_GCM
        - HPKE_X25519_HKDF_SHA256_AES128_GCMRAW
        - HPKE_X25519_HKDF_SHA256_AES256_GCM
        - HPKE_X25519_HKDF_SHA256_AES256_GCM_RAW
        - HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305
        - HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305_RAW
  ```tcl
  set keyset [::tink::aead::create_keyset "ECIES_X25519_HKDF_HMAC_SHA256_AES256_GCM"]
  ```

### Digital Signatures

* **::tink::signature::sign** *keyset_handle* *content*
    - Signs the given content with the given keyset handle and returns the resulting signature.
  ```tcl
  set signature [::tink::signature::sign $digital_signature_private_keyset_handle "hello world"]
  ```
* **::tink::signature::verify** *keyset_handle* *signature* *content*
    - Verifies the given signature against the given content with the given keyset handle and returns the resulting boolean.
  ```tcl
  set verified [::tink::signature::verify $digital_signature_public_keyset_handle $signature "hello world"]
  ```
* **::tink::signature::create_private_keyset** *signature_key_template*
    - Creates a new keyset with one key using the given key template. Supported key templates are the following:
        - ECDSA_P256
        - ECDSA_P384_SHA384
        - ECDSA_P384_SHA512
        - ECDSA_P521
        - ECDSA_P256_RAW
        - RSA_SSA_PKCS1_3072_SHA256_F4
        - RSA_SSA_PKCS1_4096_SHA512_F4
        - RSA_SSA_PSS_3072_SHA256_SHA256_F4
        - RSA_SSA_PSS_4096_SHA512_SHA512_F4
        - RSA_SSA_PSS_4096_SHA384_SHA384_F4
        - ED25519
        - ED25519_WITH_RAW_OUTPUT
  ```tcl
    set keyset [::tink::signature::create_private_keyset "ED25519"]
  ```


### Deterministic AEAD (DAEAD)

* **::tink::daead::encrypt_deterministically** *keyset_handle* *plaintext* *?associated_data?*
    - Encrypts the given plaintext with the given keyset handle and returns the resulting ciphertext.
  ```tcl
  set encrypted [::tink::daead::encrypt_deterministically $keyset_handle "someone@example.com" "email"]
  ```
* **::tink::daead::decrypt_deterministically** *keyset_handle* *ciphertext* *?associated_data?*
    - Decrypts the given ciphertext with the given keyset handle and returns the resulting plaintext.
  ```tcl
  set decrypted [::tink::daead::decrypt_deterministically $keyset_handle $encrypted "email"]
  ```
* **::tink::daead::create_keyset** *daead_key_template*
    - Creates a new keyset with one key using the given key template. Only the following key template is supported:
        - AES256_SIV
  ```tcl
  set keyset [::tink::daead::create_keyset "AES256_SIV"]
  ```

### Json Web Token (JWT)

* **::tink::jwt::sign_and_encode** *keyset_handle* *jwt_dict*
    - Signs the given JWT dictionary with the given keyset handle and returns the resulting JWT.
  The *jwt_dict* may include: audience, issuer, subject, jwt_id, expirirySeconds, and claims
  that is a list of key value pairs.
  ```tcl
  set jwt_dict [dict create \
    audience "aud" \
    issuer "iss" \
    subject "sub" \
    jwt_id "jti" \
    expirySeconds 1234567890 \
    claims [list claim1 value1 claim2 value2]]

  set token [::tink::jwt::sign_and_encode $private_keyset_handle $jwt_dict]
  ```

* **::tink::jwt::verify_and_decode** *keyset_handle* *token* *validator_dict* *?payload_varname?*
    - Verifies the given JWT against the given keyset handle and returns the result of the verification.
  If *payload_varname* is provided, it stores the payload as JSON in the corresponding var.
  ```tcl
  set validator_dict [dict create audience "aud" issuer "iss"]
  set jwt_dict [::tink::jwt::verify_and_decode $public_keyset_handle $token $validator_dict payload]
  ```

* **::tink::jwt::jwk_set_to_public_keyset** *jwk_set*
    - Converts the given JWK set to a public keyset and returns it.
  ```tcl
  set public_keyset [::tink::jwt::jwk_set_to_public_keyset $jwk_set]
  ```

* **::tink::jwt::jwk_set_from_public_keyset** *public_keyset*
    - Converts the given public keyset to a JWK set and returns it.
  ```tcl
  set jwk_set [::tink::jwt::jwk_set_from_public_keyset $public_keyset]
  ```

* **::tink::jwt::create_private_keyset** *jwt_key_template*
    - Creates a new keyset with one key using the given key template.

## Examples

* [AEAD](examples/example-aead.tcl)
* [Hybrid Encryption](examples/example-hybrid.tcl)
* [MAC](examples/example-mac.tcl)
* [Digital Signatures](examples/example-signature.tcl)
* [Deterministic AEAD](examples/example-daead.tcl)
* [JWT](examples/example-jwt.tcl)