package require tink

set digital_signature_private_keyset {{
    "primaryKeyId": 1487078030,
    "key": [
      {
        "keyData": {
          "typeUrl": "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
          "value": "Ek0SBggDEAIYAhohANUKuRXZHBD8rPcB5M6+pmgVSjk3gLSD/htdVvbrfbnPIiAXepWekQPRS74qUTMEwN6nXeizXucBxDk0SoKoeqShOBogbJEwIZASdx42tIitAe8UoBxWyi11Mq+HnWNtcQWkG18=",
          "keyMaterialType": "ASYMMETRIC_PRIVATE"
        },
        "status": "ENABLED",
        "keyId": 1487078030,
        "outputPrefixType": "TINK"
      }
    ]
  }}

set digital_signature_public_keyset {{
   "primaryKeyId": 1487078030,
   "key": [
     {
       "keyData": {
         "typeUrl": "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
         "value": "EgYIAxACGAIaIQDVCrkV2RwQ/Kz3AeTOvqZoFUo5N4C0g/4bXVb26325zyIgF3qVnpED0Uu+KlEzBMDep13os17nAcQ5NEqCqHqkoTg=",
         "keyMaterialType": "ASYMMETRIC_PUBLIC"
       },
       "status": "ENABLED",
       "keyId": 1487078030,
       "outputPrefixType": "TINK"
     }
   ]
 }}

set digital_signature_private_keyset_handle [::tink::register_keyset $digital_signature_private_keyset]
set digital_signature_public_keyset_handle [::tink::register_keyset $digital_signature_public_keyset]

set content "Hello World!"
set signature [::tink::signature::sign $digital_signature_private_keyset_handle $content]
#puts "signature: $signature"
puts "verified: [::tink::signature::verify $digital_signature_public_keyset_handle $signature $content]"
puts "verified for modified: [::tink::signature::verify $digital_signature_public_keyset_handle $signature "modified content"]"

::tink::unregister_keyset $digital_signature_private_keyset_handle
::tink::unregister_keyset $digital_signature_public_keyset_handle


set ed25519_private_keyset [::tink::signature::create_private_keyset Ed25519]
set ed25519_public_keyset [::tink::create_public_keyset $ed25519_private_keyset]

set ed25519_private_keyset_handle [::tink::register_keyset $ed25519_private_keyset]
set ed25519_public_keyset_handle [::tink::register_keyset $ed25519_public_keyset]

set content "Hello World!"
set signature [::tink::signature::sign $ed25519_private_keyset_handle $content]
#puts "signature: $signature"
puts "ed25519,verified: [::tink::signature::verify $ed25519_public_keyset_handle $signature $content]"
puts "ed25519,verified for modified: [::tink::signature::verify $ed25519_public_keyset_handle $signature "modified content"]"

::tink::unregister_keyset $ed25519_private_keyset_handle
::tink::unregister_keyset $ed25519_public_keyset_handle