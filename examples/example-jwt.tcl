package require tink

set jwt_signature_private_keyset {{
    "primaryKeyId": 185188009,
    "key": [
      {
        "keyData": {
          "typeUrl": "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
          "value": "EosCEAEagQIAs9iifvWObNLbP+x7zupVIYTdHKba4VFgJEnnGtIII21R+KGddTdvNGAokd4GPrFk1GDPitHrAAoW1+NWrafsEUi2J9Sy3uwEyarsKDggewoBCNg2fcWAiZXplPjUyTlhrLvTuyrcL/mGPy+ib7bdmov+D2EP+rKUH6/ydtQGiyHRR3uurTUWfrMD1/6WaBVfngpy5Pxs2nuHXRmBHQKWmPfvErgr4abdjhKDaWIuxzSise1CSAbiWTNcxpIuFYZgPjgQzpqeh93LUXIX9YJds/bhHtXqRdxk6yTisloHOZETItK/rHCCE25dLkkaJ2Li7AtnJdBc6tEUNiuFj2JCjSIDAQABGoACT2lWxwySaQbp/N3lBUZ/dJ+AKsiaWWdfNmbTfwpCwbHhwhFKv5lMpynWgCIzS7d0uDpPKhLq20eZMpaVjXRaTn92vzuyB7DbpFiukkvGO839CvS9iueMjDP/weHlwzxtHqKJKVoRg7WAS6Iy7XUngLhT5GKNdbsooJ1GSKXyhbgWyMcspKSQe4lZXUntVMK5z4iLNmcQwsBp8yM55mZra13TXowob/E/wd+tGiABCn6CDt8G1gXzWDaoF2tt6WhSGZbXUVGagmoea/BWeAuJyKSSi5h+uPpc5SPhGvyKfSEVaCs2QeM7/UIXhzAcx2j/VqySb6y9EbSiJfy8vr49QSKBAQD+AbFCGHd9kZ5LIQrfe9caOxS9pQPdFkBJESw0C3x2uBIg8awiQsuVXMeEgyGLyWBZoi2x98OMSR9OzCuSLtb7Nv0Wqn0LUj4WPRdmg//uLeD3O2rcVRIR4db/B8WvXnK2uQsqwGDyh4BepGvprXQPYMX2uwnBGL2ccS2De53HJSqBAQC1QfOi4egjmlmXqJLpISUSN1NixkIi8EJHaZZ0YrbaRrEyiJczthcazNHFt6gzgOcosFaKaZeqps4Tet+5NgS7eh7RzLQ2+cfT4ewpT2ExJ4NsOy8XDqD6GRjliLxjGAoUf24s3B+3LLACPiQjeeZGJP0ivh384WabyXXxRgHFSTKBAQChl7gKIYCbHPHEQAAnzyQ4Js/6GinMFCTPlyI09f23lUDLPpRQs4fKvNydO8Myp+ko/NjvOH1qGPbW7WLmu+++n+wA6HNmqWqgQTtK170Q7JULE/zWsTQutitN0cb82yxFfJFTIFJM2NFc5GNWpSeJxPoMDk+VTcUK6qGW3SSyFTqBAQCeaPFA3SZAV1kNjio2zNzVOr0JijOqzUdfmgv/03Xy9e1POMjMTMuMhIygu42o1XMwwEwh037Vicp4g96aw3cHUgc1XC30DgByUPRQdit/BgV5xY+2GvbdHKoBkKrz/8Jvf58OXaLqN4frrdtvlc2GaDVC89zJcUR3ym3lW0WY4UKBAQD6MCruwXaxXJMxjtlH1YT5ow4R5neeiswNfGj4Ta/WbWyiVA60zpdNbGqH+etmiHY8+aBb/H4O9+JhOcBtlMLN4UlK1jg8wPSemZjsIPiUZXHkeIUa2RTUSz90wgz7aOqC0lYsLLFaJNWs54fC9LpZ0JzoqYDI8iDPnlE7xaag9g==",
          "keyMaterialType": "ASYMMETRIC_PRIVATE"
        },
        "status": "ENABLED",
        "keyId": 185188009,
        "outputPrefixType": "TINK"
      }
    ]
  }}

set jwt_signature_public_keyset {{
   "primaryKeyId": 185188009,
   "key": [
     {
       "keyData": {
         "typeUrl": "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
         "value": "EAEagQIAs9iifvWObNLbP+x7zupVIYTdHKba4VFgJEnnGtIII21R+KGddTdvNGAokd4GPrFk1GDPitHrAAoW1+NWrafsEUi2J9Sy3uwEyarsKDggewoBCNg2fcWAiZXplPjUyTlhrLvTuyrcL/mGPy+ib7bdmov+D2EP+rKUH6/ydtQGiyHRR3uurTUWfrMD1/6WaBVfngpy5Pxs2nuHXRmBHQKWmPfvErgr4abdjhKDaWIuxzSise1CSAbiWTNcxpIuFYZgPjgQzpqeh93LUXIX9YJds/bhHtXqRdxk6yTisloHOZETItK/rHCCE25dLkkaJ2Li7AtnJdBc6tEUNiuFj2JCjSIDAQAB",
         "keyMaterialType": "ASYMMETRIC_PUBLIC"
       },
       "status": "ENABLED",
       "keyId": 185188009,
       "outputPrefixType": "TINK"
     }
   ]
 }}

set private_keyset_handle [::tink::register_keyset $jwt_signature_private_keyset]
set payload [dict create audience "aud" issuer "iss" subject "sub" jwt_id "jti" expirySeconds 1234567890]
set token [::tink::jwt::sign_and_encode $private_keyset_handle $payload]
puts token=$token