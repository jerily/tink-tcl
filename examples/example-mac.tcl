package require tink

set hmac_keyset {{
    "primaryKeyId": 691856985,
    "key": [
      {
        "keyData": {
          "typeUrl": "type.googleapis.com/google.crypto.tink.HmacKey",
          "keyMaterialType": "SYMMETRIC",
          "value": "EgQIAxAgGiDZsmkTufMG/XlKlk9m7bqxustjUPT2YULEVm8mOp2mSA=="
        },
        "outputPrefixType": "TINK",
        "keyId": 691856985,
        "status": "ENABLED"
      }
    ]
}}
set hmac_keyset_handle [::tink::register_keyset $hmac_keyset]
set content "hello world"
set tag [::tink::mac::compute $hmac_keyset_handle $content]
#puts mac,authentication_tag=$tag
set verified [::tink::mac::verify $hmac_keyset_handle $tag $content]
puts verified=$verified
::tink::unregister_keyset $hmac_keyset_handle

set new_hmac_keyset [::tink::mac::create_keyset "HmacSha256"]
set new_hmac_keyset_handle [::tink::register_keyset $new_hmac_keyset]
set new_tag [::tink::mac::compute $new_hmac_keyset_handle $content]
#puts new_mac,authentication_tag=$new_tag
set new_verified [::tink::mac::verify $new_hmac_keyset_handle $new_tag $content]
puts new_verified=$new_verified
::tink::unregister_keyset $new_hmac_keyset_handle