# tink-tcl

Tcl bindings for [Tink](https://github.com/tink-crypto/tink-cc), a multi-language, cross-platform library that provides cryptographic APIs that are secure, easy to use correctly, and hard(er) to misuse.

## Clone the repository
```bash
git clone https://github.com/jerily/tink-tcl.git
cd tink-tcl
export TINK_TCL_DIR=`pwd`
```

## Install dependencies
```bash

#abseil
wget https://github.com/abseil/abseil-cpp/archive/refs/tags/20230125.0.tar.gz
tar -xzf 20230125.0.tar.gz
cd abseil-cpp-20230125.0
mkdir build
cd build
cmake .. \
  -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr/local
make
make install

#tink
wget https://github.com/tink-crypto/tink-cc/archive/refs/tags/v2.0.0.tar.gz
tar -xzf v2.0.0.tar.gz
cd tink-cc-2.0.0
patch -p1 < ${TINK_TCL_DIR}/tink-cc-2.0.0.diff
mkdir build
cd build
cmake .. \
  -DTINK_BUILD_SHARED_LIB=ON \
  -DTINK_USE_INSTALLED_ABSEIL=ON \
  -DTINK_USE_SYSTEM_OPENSSL=OFF \
  -DTINK_USE_INSTALLED_PROTOBUF=OFF \
  -DTINK_USE_INSTALLED_RAPIDJSON=OFF \
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
    - Creates a new public keyset from the given private keyset and returns a handle.
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
