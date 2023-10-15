package require tink

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
set plaintext "hello world"
set associated_data "some associated data"
set encrypted [::tink::aead::encrypt $keyset_handle $plaintext $associated_data]
set decrypted [::tink::aead::decrypt $keyset_handle $encrypted $associated_data]
#puts encrypted=[string range $encrypted 0 40]
puts decrypted=$decrypted
::tink::unregister_keyset $keyset_handle


set new_keyset [::tink::aead::create_keyset "AES256_GCM"]
puts new_keyset=$new_keyset
set new_keyset_handle [::tink::register_keyset $new_keyset]
set new_encrypted [::tink::aead::encrypt $new_keyset_handle $plaintext $associated_data]
set new_decrypted [::tink::aead::decrypt $new_keyset_handle $new_encrypted $associated_data]
#puts new_encrypted=[string range $new_encrypted 0 40]
puts new_decrypted=$new_decrypted
::tink::unregister_keyset $new_keyset_handle
