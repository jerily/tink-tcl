package require tink

set hybrid_test_private_keyset {{
  "primaryKeyId": 548859458,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
        "value": "EowBEkQKBAgCEAMSOhI4CjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNHY21LZXkSAhAQGAEYARohAKjjAxgGmD9j90UyzNunoC04kWqaWiXGFRhOYfLS7Z2tIiEAhqqb+D0Din92zHwGQefzui0hma5khIZQCWyWHHVgNpsaIBQrEEuEn3hClVKM+4bsvmaUOqFYMbl7E6lNFJzbr+lp",
        "keyMaterialType": "ASYMMETRIC_PRIVATE"
      },
      "status": "ENABLED",
      "keyId": 548859458,
      "outputPrefixType": "TINK"
    }
  ]
}}

set hybrid_test_public_keyset {{
 "primaryKeyId": 548859458,
 "key": [
   {
     "keyData": {
       "typeUrl": "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
       "value": "EkQKBAgCEAMSOhI4CjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNHY21LZXkSAhAQGAEYARohAKjjAxgGmD9j90UyzNunoC04kWqaWiXGFRhOYfLS7Z2tIiEAhqqb+D0Din92zHwGQefzui0hma5khIZQCWyWHHVgNps=",
       "keyMaterialType": "ASYMMETRIC_PUBLIC"
     },
     "status": "ENABLED",
     "keyId": 548859458,
     "outputPrefixType": "TINK"
   }
 ]
}}


set hybrid_test_private_keyset_handle [::tink::register_keyset $hybrid_test_private_keyset]
set hybrid_test_public_keyset_handle [::tink::register_keyset $hybrid_test_public_keyset]

set plaintext "hello world"
set context_info "some context info"
set encrypted [::tink::hybrid::encrypt $hybrid_test_public_keyset_handle $plaintext $context_info]
set decrypted [::tink::hybrid::decrypt $hybrid_test_private_keyset_handle $encrypted $context_info]
puts decrypted=$decrypted

::tink::unregister_keyset $hybrid_test_private_keyset_handle
::tink::unregister_keyset $hybrid_test_public_keyset_handle

set hpke_test_private_keyset {{
    "primaryKeyId": 958452012,
    "key": [
      {
        "keyData": {
          "typeUrl": "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
          "value": "EioSBggBEAEYAhogVWQpmQoz74jcAp5WOD36KiBQ71MVCpn2iWfOzWLtKV4aINfn8qlMbyijNJcCzrafjsgJ493ZZGN256KTfKw0WN+p",
          "keyMaterialType": "ASYMMETRIC_PRIVATE"
        },
        "status": "ENABLED",
        "keyId": 958452012,
        "outputPrefixType": "TINK"
      }
    ]
  }}


set new_hybrid_test_private_keyset [::tink::hybrid::create_private_keyset "EciesX25519HkdfHmacSha256Aes256Gcm"]
puts new_hybrid_test_private_keyset=$new_hybrid_test_private_keyset
set new_hybrid_test_public_keyset [::tink::create_public_keyset $new_hybrid_test_private_keyset]
puts new_hybrid_test_public_keyset=$new_hybrid_test_public_keyset

set new_hybrid_test_private_keyset_handle [::tink::register_keyset $new_hybrid_test_private_keyset]
set new_hybrid_test_public_keyset_handle [::tink::register_keyset $new_hybrid_test_public_keyset]

set plaintext "hello world"
set context_info "some context info"
set encrypted [::tink::hybrid::encrypt $new_hybrid_test_public_keyset_handle $plaintext $context_info]
set decrypted [::tink::hybrid::decrypt $new_hybrid_test_private_keyset_handle $encrypted $context_info]
puts new_hybrid,decrypted=$decrypted

::tink::unregister_keyset $new_hybrid_test_private_keyset_handle
::tink::unregister_keyset $new_hybrid_test_public_keyset_handle
