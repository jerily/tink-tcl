package require tink

set keyset {{
  "primaryKeyId": 1184417862,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.AesSivKey",
        "value": "EkAbqs8wuMAXvuqU9FVOW9VvG9kE9P3aI5qjnkGvNTeRh/Cxoh06kosU5R9jRCHCkdMgnOSHMtfIKkQj5exuhesH",
        "keyMaterialType": "SYMMETRIC"
      },
      "status": "ENABLED",
      "keyId": 1184417862,
      "outputPrefixType": "TINK"
    }
  ]
}}
set keyset_handle [::tink::register_keyset $keyset]
set plaintext "hello world"
set associated_data "some associated data"
set encrypted [::tink::daead::encrypt_deterministically $keyset_handle $plaintext $associated_data]
set decrypted [::tink::daead::decrypt_deterministically $keyset_handle $encrypted $associated_data]
#puts encrypted=[string range $encrypted 0 40]
puts decrypted=$decrypted
::tink::unregister_keyset $keyset_handle


set new_keyset [::tink::daead::create_keyset "AES256_SIV"]
puts new_keyset=$new_keyset
set new_keyset_handle [::tink::register_keyset $new_keyset]
set new_encrypted [::tink::daead::encrypt_deterministically $new_keyset_handle $plaintext $associated_data]
set new_decrypted [::tink::daead::decrypt_deterministically $new_keyset_handle $new_encrypted $associated_data]
#puts new_encrypted=[string range $new_encrypted 0 40]
puts new_decrypted=$new_decrypted
::tink::unregister_keyset $new_keyset_handle
