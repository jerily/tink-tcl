#set PROJECT_DIR /path/to/your/project
set PROJECT_DIR /home/phi/openacs/sample-project/tcl_modules/
set auto_path [linsert $auto_path 0 ${PROJECT_DIR}/lib]
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


set new_keyset [::tink::aead::create_keyset "Aes128Gcm"]
puts new_keyset=$new_keyset
set new_keyset_handle [::tink::register_keyset $new_keyset]
set new_encrypted [::tink::aead::encrypt $new_keyset_handle $plaintext $associated_data]
set new_decrypted [::tink::aead::decrypt $new_keyset_handle $new_encrypted $associated_data]
#puts new_encrypted=[string range $new_encrypted 0 40]
puts new_decrypted=$new_decrypted
::tink::unregister_keyset $new_keyset_handle

# using LocalStack, you can get a KMS key uri like this:
# awslocal kms create-key
# and when you run this example, you can run it as follows:
# AWS_ENDPOINT_URL="http://localhost:4566" tclsh ../examples/example.tcl
#set master_kms_key_uri "aws-kms://arn:aws:kms:us-east-1:000000000000:key/f8def55d-0283-4f60-8d97-169bd1a7aaba"
#set kms_client_config_dict [dict create endpoint "http://localhost:4566" region "us-east-1"]
#set encrypted_keyset [::tink::aead::create_keyset "Aes128Gcm" $master_kms_key_uri $kms_client_config_dict]
#puts encrypted_keyset=$encrypted_keyset