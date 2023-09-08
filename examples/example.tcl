#set PROJECT_DIR /path/to/your/project
set PROJECT_DIR /home/phi/openacs/sample-project/tcl_modules/
lappend auto_path ${PROJECT_DIR}/lib
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
set plaintext "hello world"
set associated_data "some associated data"
set encrypted [::tink::aead::encrypt $keyset $plaintext $associated_data]
set decrypted [::tink::aead::decrypt $keyset $encrypted $associated_data]
#puts encrypted=[string range $encrypted 0 40]
puts decrypted=$decrypted

set new_keyset [::tink::aead::create_keyset "Aes128Gcm"]
puts new_keyset=$new_keyset
set new_encrypted [::tink::aead::encrypt $new_keyset $plaintext $associated_data]
set new_decrypted [::tink::aead::decrypt $new_keyset $new_encrypted $associated_data]
#puts new_encrypted=[string range $new_encrypted 0 40]
puts new_decrypted=$new_decrypted
