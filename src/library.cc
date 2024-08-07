/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#include <iostream>
#include <cstdio>
#include <fstream>
#include <tink/config/tink_config.h>
#include <tink/keyset_handle.h>
#include <tink/json_keyset_reader.h>
#include <tink/json_keyset_writer.h>
#include <tink/cleartext_keyset_handle.h>
#include <tink/aead.h>
#include <tink/aead/aead_key_templates.h>
#include <tink/deterministic_aead.h>
#include <tink/deterministic_aead_key_templates.h>
#include <tink/mac.h>
#include <tink/mac/mac_key_templates.h>
#include <tink/hybrid_encrypt.h>
#include <tink/hybrid_decrypt.h>
#include <tink/hybrid_key_templates.h>
#include <tink/public_key_sign.h>
#include <tink/public_key_verify.h>
#include <tink/signature_key_templates.h>
#include <tink/jwt/jwt_public_key_sign.h>
#include <tink/jwt/jwt_public_key_verify.h>
#include <tink/jwt/jwt_validator.h>
#include <tink/jwt/jwk_set_converter.h>
#include <tink/jwt/jwt_signature_config.h>
#include <tink/jwt/jwt_key_templates.h>
#include <tink/jwt/jwt_mac_config.h>
#include "library.h"

#ifndef TCL_SIZE_MAX
typedef int Tcl_Size;
# define Tcl_GetSizeIntFromObj Tcl_GetIntFromObj
# define Tcl_NewSizeIntObj Tcl_NewIntObj
# define TCL_SIZE_MAX      INT_MAX
# define TCL_SIZE_MODIFIER ""
#endif

#define XSTR(s) STR(s)
#define STR(s) #s

#ifdef DEBUG
# define DBG(x) x
#else
# define DBG(x)
#endif

#define CheckArgs(min, max, n, msg) \
                 if ((objc < min) || (objc >max)) { \
                     Tcl_WrongNumArgs(interp, n, objv, msg); \
                     return TCL_ERROR; \
                 }

#define SetResult(str) Tcl_ResetResult(interp); \
                     Tcl_SetStringObj(Tcl_GetObjResult(interp), (str), -1)

#define CMD_KEYSET_NAME(s, internal) sprintf((s), "_TINK_KS_%p", (internal))

using crypto::tink::TinkConfig;
using crypto::tink::JsonKeysetReader;
using crypto::tink::JsonKeysetWriter;
using crypto::tink::CleartextKeysetHandle;
using crypto::tink::KeysetHandle;
using google::crypto::tink::KeyTemplate;
using crypto::tink::Aead;
using crypto::tink::AeadKeyTemplates;
using crypto::tink::Mac;
using crypto::tink::MacKeyTemplates;
using crypto::tink::HybridEncrypt;
using crypto::tink::HybridDecrypt;
using crypto::tink::HybridKeyTemplates;
using crypto::tink::PublicKeySign;
using crypto::tink::PublicKeyVerify;
using crypto::tink::SignatureKeyTemplates;
using crypto::tink::DeterministicAead;
using crypto::tink::DeterministicAeadKeyTemplates;
using ::crypto::tink::RawJwt;
using ::crypto::tink::RawJwtBuilder;
using ::crypto::tink::JwtPublicKeySign;
using ::crypto::tink::JwtPublicKeyVerify;
using ::crypto::tink::JwtValidator;
using ::crypto::tink::VerifiedJwt;
using ::crypto::tink::JwkSetFromPublicKeysetHandle;
using ::crypto::tink::JwkSetToPublicKeysetHandle;
using ::crypto::tink::JwtSignatureRegister;
using ::crypto::tink::JwtValidatorBuilder;
using ::crypto::tink::JwtMacRegister;

static int tink_ModuleInitialized;

static Tcl_HashTable tink_KeysetNameToInternal_HT;
static Tcl_Mutex tink_KeysetNameToInternal_HT_Mutex;

typedef struct {
    KeysetHandle *keyset_handle;
} tink_keyset_t;

int tink_RegisterKeysetName(const char *name, tink_keyset_t *internal) {

    Tcl_HashEntry *entryPtr;
    int newEntry;
    Tcl_MutexLock(&tink_KeysetNameToInternal_HT_Mutex);
    entryPtr = Tcl_CreateHashEntry(&tink_KeysetNameToInternal_HT, (char *) name, &newEntry);
    if (newEntry) {
        Tcl_SetHashValue(entryPtr, (ClientData) internal);
    }
    Tcl_MutexUnlock(&tink_KeysetNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> RegisterKeysetName: name=%s internal=%p %s\n", name, internal,
                newEntry ? "entered into" : "already in"));

    return newEntry;
}

int tink_UnregisterKeysetName(const char *name) {

    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tink_KeysetNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tink_KeysetNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        Tcl_DeleteHashEntry(entryPtr);
    }
    Tcl_MutexUnlock(&tink_KeysetNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> UnregisterKeysetName: name=%s entryPtr=%p\n", name, entryPtr));

    return entryPtr != NULL;
}

tink_keyset_t *tink_GetInternalFromKeysetName(const char *name) {
    tink_keyset_t *internal = NULL;
    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tink_KeysetNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tink_KeysetNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        internal = (tink_keyset_t *) Tcl_GetHashValue(entryPtr);
    }
    Tcl_MutexUnlock(&tink_KeysetNameToInternal_HT_Mutex);

    return internal;
}


static int tink_RegisterKeysetCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "RegisterKeysetCmd\n"));
    CheckArgs(2, 2, 1, "keyset");

    absl::string_view keyset = Tcl_GetString(objv[1]);
    auto reader_result = JsonKeysetReader::New(keyset);
    if (!reader_result.ok()) {
        SetResult("Error creating reader");
        return TCL_ERROR;
    }

    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = CleartextKeysetHandle::Read(
            *std::move(reader_result));
    if (!keyset_handle.ok()) {
        SetResult("Error reading keyset");
        return TCL_ERROR;
    }

    auto keyset_ptr = (tink_keyset_t *) Tcl_Alloc(sizeof(tink_keyset_t));
    if (keyset_ptr == nullptr) {
        SetResult("Error allocating memory");
        return TCL_ERROR;
    }
    keyset_ptr->keyset_handle = (*keyset_handle).release();
    char keyset_name[40];
    CMD_KEYSET_NAME(keyset_name, keyset_ptr->keyset_handle);
    DBG(fprintf(stderr, "keyset_name=%s\n", keyset_name));
    tink_RegisterKeysetName(keyset_name, keyset_ptr);

    SetResult(keyset_name);
    return TCL_OK;
}

static int tink_UnregisterKeysetCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "UnregisterKeysetCmd\n"));
    CheckArgs(2, 2, 1, "keyset_handle");
    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        SetResult("keyset handle not found");
        return TCL_ERROR;
    }
    tink_UnregisterKeysetName(keyset_name);
    delete keyset_ptr->keyset_handle;
    Tcl_Free((char *) keyset_ptr);
    return TCL_OK;
}

static int tink_CreatePublicKeysetCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "CreatePublicKeysetCmd\n"));
    CheckArgs(2, 2, 1, "private_keyset");

    absl::string_view private_keyset = Tcl_GetString(objv[1]);
    auto reader_result = JsonKeysetReader::New(private_keyset);
    if (!reader_result.ok()) {
        SetResult("Error creating reader");
        return TCL_ERROR;
    }

    absl::StatusOr<std::unique_ptr<KeysetHandle>> private_keyset_handle = CleartextKeysetHandle::Read(
            *std::move(reader_result));
    if (!private_keyset_handle.ok()) {
        SetResult("Error reading keyset_handle");
        return TCL_ERROR;
    }

    auto public_keyset_handle = (*private_keyset_handle)->GetPublicKeysetHandle();
    if (!public_keyset_handle.ok()) {
        SetResult("Error getting public keyset handle");
        return TCL_ERROR;
    }

    std::stringbuf buffer;
    auto output_stream = absl::make_unique<std::ostream>(&buffer);

    absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> keyset_writer = JsonKeysetWriter::New(std::move(output_stream));
    if (!keyset_writer.ok()) {
        SetResult("Error creating writer");
        return TCL_ERROR;
    }

    absl::Status status = CleartextKeysetHandle::Write((keyset_writer)->get(), **public_keyset_handle);;
    if (!status.ok()) {
        SetResult("Error writing keyset");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewStringObj(buffer.str().c_str(), buffer.str().size()));
    return TCL_OK;
}

static int tink_AeadEncryptCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AeadEncryptCmd\n"));
    CheckArgs(3, 4, 1, "keyset_handle plaintext ?associated_data?");

    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        SetResult("keyset handle not found");
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    auto valid = keyset_handle->Validate();
    if (!valid.ok()) {
        SetResult("error validating keyset");
        return TCL_ERROR;
    }

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<Aead>> aead_primitive = keyset_handle->GetPrimitive<Aead>();
    if (!aead_primitive.ok()) {
        SetResult("error getting primitive");
        return TCL_ERROR;
    }

    Tcl_Size plaintext_length;
    const unsigned char *plaintext = Tcl_GetByteArrayFromObj(objv[2], &plaintext_length);
    absl::StatusOr<std::string> plaintext_str = std::string((const char *) plaintext, plaintext_length);

    Tcl_Size associated_data_length;
    auto associated_data = (objc == 4) ? Tcl_GetByteArrayFromObj(objv[3], &associated_data_length) : nullptr;
    absl::string_view associated_data_str = (objc == 4) ? absl::string_view((const char *) associated_data,
                                                                            associated_data_length) : "";

    absl::StatusOr<std::string> encrypt_result =
            (*aead_primitive)->Encrypt(*plaintext_str, associated_data_str);

    if (!encrypt_result.ok()) {
        SetResult("error encrypting");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((const unsigned char *) encrypt_result.value().data(),
                                                 encrypt_result.value().size()));
    return TCL_OK;
}

static int tink_AeadDecryptCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AeadDecryptCmd\n"));
    CheckArgs(3, 4, 1, "keyset_handle ciphertext ?associated_data?");

    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        SetResult("keyset handle not found");
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<Aead>> aead_primitive = keyset_handle->GetPrimitive<Aead>();
    if (!aead_primitive.ok()) {
        SetResult("error getting primitive");
        return TCL_ERROR;
    }

    Tcl_Size ciphertext_length;
    const unsigned char *ciphertext = Tcl_GetByteArrayFromObj(objv[2], &ciphertext_length);
    absl::StatusOr<std::string> ciphertext_str = std::string((const char *) ciphertext, ciphertext_length);

    Tcl_Size associated_data_length;
    auto associated_data = (objc == 4) ? Tcl_GetByteArrayFromObj(objv[3], &associated_data_length) : nullptr;
    absl::string_view associated_data_str = (objc == 4) ? absl::string_view((const char *) associated_data,
                                                                            associated_data_length) : "";
    absl::StatusOr<std::string> decrypt_result =
            (*aead_primitive)->Decrypt(*ciphertext_str, associated_data_str);

    if (!decrypt_result.ok()) {
        SetResult("error decrypting");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((const unsigned char *) decrypt_result.value().data(),
                                                 decrypt_result.value().size()));
    return TCL_OK;
}

static int tink_AeadCreateKeysetCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AeadCreateKeysetCmd\n"));
    CheckArgs(2, 2, 1, "aead_key_template");

    static const char *aead_key_template_names[] = {
            "AES128_EAX",
            "AES256_EAX",
            "AES128_GCM",
            "AES128_GCM_NO_PREFIX",
            "AES256_GCM",
            "AES256_GCM_NO_PREFIX",
            "AES128_GCM_SIV",
            "AES256_GCM_SIV",
            "AES128_CTR_HMAC_SHA256",
            "AES256_CTR_HMAC_SHA256",
            "XCHACHA20_POLY1305",
            nullptr
    };

    enum aead_key_templates {
        Aes128Eax,
        Aes256Eax,
        Aes128Gcm,
        Aes128GcmNoPrefix,
        Aes256Gcm,
        Aes256GcmNoPrefix,
        Aes128GcmSiv,
        Aes256GcmSiv,
        Aes128CtrHmacSha256,
        Aes256CtrHmacSha256,
        XChaCha20Poly1305
    };

    int key_template_index;
    if (TCL_OK !=
        Tcl_GetIndexFromObj(interp, objv[1], aead_key_template_names, "aead key template", 0, &key_template_index)) {
        SetResult("Unknown aead key template");
        return TCL_ERROR;
    }

    KeyTemplate key_template;
    switch ((enum aead_key_templates) key_template_index) {
        case Aes128Eax:
            key_template = AeadKeyTemplates::Aes128Eax();
            break;
        case Aes256Eax:
            key_template = AeadKeyTemplates::Aes256Eax();
            break;
        case Aes128Gcm:
            key_template = AeadKeyTemplates::Aes128Gcm();
            break;
        case Aes128GcmNoPrefix:
            key_template = AeadKeyTemplates::Aes128GcmNoPrefix();
            break;
        case Aes256Gcm:
            key_template = AeadKeyTemplates::Aes256Gcm();
            break;
        case Aes256GcmNoPrefix:
            key_template = AeadKeyTemplates::Aes256GcmNoPrefix();
            break;
        case Aes128GcmSiv:
            key_template = AeadKeyTemplates::Aes128GcmSiv();
            break;
        case Aes256GcmSiv:
            key_template = AeadKeyTemplates::Aes256GcmSiv();
            break;
        case Aes128CtrHmacSha256:
            key_template = AeadKeyTemplates::Aes128CtrHmacSha256();
            break;
        case Aes256CtrHmacSha256:
            key_template = AeadKeyTemplates::Aes256CtrHmacSha256();
            break;
        case XChaCha20Poly1305:
            key_template = AeadKeyTemplates::XChaCha20Poly1305();
            break;
        default:
        SetResult("Unknown aead key template");
            return TCL_ERROR;
    }

    // This will generate a new keyset with only *one* key and return a keyset handle to it.
    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = KeysetHandle::GenerateNew(key_template);
    if (!keyset_handle.ok()) {
        SetResult("Error generating keyset");
        return TCL_ERROR;
    }

    std::stringbuf buffer;
    auto output_stream = absl::make_unique<std::ostream>(&buffer);

    absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> keyset_writer = JsonKeysetWriter::New(std::move(output_stream));
    if (!keyset_writer.ok()) {
        SetResult("Error creating writer");
        return TCL_ERROR;
    }

    absl::Status status = CleartextKeysetHandle::Write((keyset_writer)->get(), **keyset_handle);;
    if (!status.ok()) {
        SetResult("Error writing keyset");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewStringObj(buffer.str().c_str(), buffer.str().size()));
    return TCL_OK;
}

static int tink_MacComputeCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "MacComputeCmd\n"));
    CheckArgs(3, 3, 1, "keyset_handle content");

    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        SetResult("keyset handle not found");
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    auto valid = keyset_handle->Validate();
    if (!valid.ok()) {
        SetResult("error validating keyset");
        return TCL_ERROR;
    }

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<Mac>> mac_primitive = keyset_handle->GetPrimitive<Mac>();
    if (!mac_primitive.ok()) {
        SetResult("error getting primitive");
        return TCL_ERROR;
    }

    Tcl_Size content_length;
    const unsigned char *content = Tcl_GetByteArrayFromObj(objv[2], &content_length);
    std::string content_str = std::string((const char *) content, content_length);
    absl::StatusOr<std::string> compute_result = (*mac_primitive)->ComputeMac(content_str);
    if (!compute_result.ok()) {
        SetResult("error computing mac");
        return TCL_ERROR;
    }

    // return the authentication tag
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((const unsigned char *) compute_result.value().data(),
                                                 compute_result.value().size()));
    return TCL_OK;
}

static int tink_MacVerifyCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "MacVerifyCmd\n"));
    CheckArgs(4, 4, 1, "keyset_handle tag content");

    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        SetResult("keyset handle not found");
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    auto valid = keyset_handle->Validate();
    if (!valid.ok()) {
        SetResult("error validating keyset");
        return TCL_ERROR;
    }

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<Mac>> mac_primitive = keyset_handle->GetPrimitive<Mac>();
    if (!mac_primitive.ok()) {
        SetResult("error getting primitive");
        return TCL_ERROR;
    }

    Tcl_Size tag_length;
    const unsigned char *tag = Tcl_GetByteArrayFromObj(objv[2], &tag_length);
    std::string tag_str = std::string((const char *) tag, tag_length);

    Tcl_Size content_length;
    const unsigned char *content = Tcl_GetByteArrayFromObj(objv[3], &content_length);
    std::string content_str = std::string((const char *) content, content_length);

    // Verifies if 'mac' is a correct authentication code (MAC) for 'data'.
    // Returns Status::OK if 'mac' is correct, and a non-OK-Status otherwise.
    absl::Status verify_result = (*mac_primitive)->VerifyMac(tag_str, content_str);

    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(verify_result.ok()));
    return TCL_OK;
}

static int tink_MacCreateKeysetCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "MacCreateKeysetCmd\n"));
    CheckArgs(2, 2, 1, "mac_key_template");

    static const char *mac_key_template_names[] = {
            "HMAC_SHA256_128BITTAG",
            "HMAC_SHA256",
            "HMAC_SHA512_256BITTAG",
            "HMAC_SHA512",
            "AES_CMAC",
            nullptr
    };

    enum mac_key_templates {
        HmacSha256HalfSizeTag,
        HmacSha256,
        HmacSha512HalfSizeTag,
        HmacSha512,
        AesCmac
    };

    int key_template_index;
    if (TCL_OK !=
        Tcl_GetIndexFromObj(interp, objv[1], mac_key_template_names, "mac key template", 0, &key_template_index)) {
        SetResult("Unknown mac key template");
        return TCL_ERROR;
    }

    KeyTemplate key_template;
    switch ((enum mac_key_templates) key_template_index) {
        case HmacSha256HalfSizeTag:
            key_template = MacKeyTemplates::HmacSha256HalfSizeTag();
            break;
        case HmacSha256:
            key_template = MacKeyTemplates::HmacSha256();
            break;
        case HmacSha512HalfSizeTag:
            key_template = MacKeyTemplates::HmacSha512HalfSizeTag();
            break;
        case HmacSha512:
            key_template = MacKeyTemplates::HmacSha512();
            break;
        case AesCmac:
            key_template = MacKeyTemplates::AesCmac();
            break;
        default:
        SetResult("Unknown mac key template");
            return TCL_ERROR;
    }

    // This will generate a new keyset with only *one* key and return a keyset handle to it.
    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = KeysetHandle::GenerateNew(key_template);
    if (!keyset_handle.ok()) {
        SetResult("Error generating keyset");
        return TCL_ERROR;
    }

    std::stringbuf buffer;
    auto output_stream = absl::make_unique<std::ostream>(&buffer);

    absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> keyset_writer = JsonKeysetWriter::New(std::move(output_stream));
    if (!keyset_writer.ok()) {
        SetResult("Error creating writer");
        return TCL_ERROR;
    }

    absl::Status status = CleartextKeysetHandle::Write((keyset_writer)->get(), **keyset_handle);;
    if (!status.ok()) {
        SetResult("Error writing keyset");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewStringObj(buffer.str().c_str(), buffer.str().size()));
    return TCL_OK;
}

static int tink_HybridEncryptCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "HybridEncryptCmd\n"));
    CheckArgs(3, 4, 1, "keyset_handle plaintext ?context_info?");

    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        SetResult("keyset handle not found");
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    auto valid = keyset_handle->Validate();
    if (!valid.ok()) {
        SetResult("error validating keyset");
        return TCL_ERROR;
    }

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<HybridEncrypt>> hybrid_encrypt_primitive = keyset_handle->GetPrimitive<HybridEncrypt>();
    if (!hybrid_encrypt_primitive.ok()) {
        SetResult("error getting primitive");
        return TCL_ERROR;
    }

    Tcl_Size plaintext_length;
    const unsigned char *plaintext = Tcl_GetByteArrayFromObj(objv[2], &plaintext_length);
    absl::StatusOr<std::string> plaintext_str = std::string((const char *) plaintext, plaintext_length);

    Tcl_Size context_info_length;
    auto context_info = (objc == 4) ? Tcl_GetByteArrayFromObj(objv[3], &context_info_length) : nullptr;
    absl::string_view context_info_str = (objc == 4) ? absl::string_view((const char *) context_info,
                                                                         context_info_length) : "";

    absl::StatusOr<std::string> encrypt_result =
            (*hybrid_encrypt_primitive)->Encrypt(*plaintext_str, context_info_str);

    if (!encrypt_result.ok()) {
        SetResult("error encrypting");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((const unsigned char *) encrypt_result.value().data(),
                                                 encrypt_result.value().size()));
    return TCL_OK;
}

static int tink_HybridDecryptCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "HybridDecryptCmd\n"));
    CheckArgs(3, 4, 1, "keyset_handle ciphertext ?context_info?");

    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        SetResult("keyset handle not found");
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<HybridDecrypt>> hybrid_decrypt_primitive = keyset_handle->GetPrimitive<HybridDecrypt>();
    if (!hybrid_decrypt_primitive.ok()) {
        SetResult("error getting primitive");
        return TCL_ERROR;
    }

    Tcl_Size ciphertext_length;
    const unsigned char *ciphertext = Tcl_GetByteArrayFromObj(objv[2], &ciphertext_length);
    absl::StatusOr<std::string> ciphertext_str = std::string((const char *) ciphertext, ciphertext_length);

    Tcl_Size context_info_length;
    auto context_info = (objc == 4) ? Tcl_GetByteArrayFromObj(objv[3], &context_info_length) : nullptr;
    absl::string_view context_info_str = (objc == 4) ? absl::string_view((const char *) context_info,
                                                                         context_info_length) : "";
    absl::StatusOr<std::string> decrypt_result =
            (*hybrid_decrypt_primitive)->Decrypt(*ciphertext_str, context_info_str);

    if (!decrypt_result.ok()) {
        SetResult("error decrypting");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((const unsigned char *) decrypt_result.value().data(),
                                                 decrypt_result.value().size()));
    return TCL_OK;
}

static int
tink_HybridCreatePrivateKeysetCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "HybridCreatePrivateKeysetCmd\n"));
    CheckArgs(2, 2, 1, "hybrid_key_template");

    static const char *hybrid_key_template_names[] = {
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
            "ECIES_P256_HKDF_HMAC_SHA512_AES128_GCM",
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_NO_PREFIX",
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
            "ECIES_P256_HKDF_HMAC_SHA512_AES128_CTR_HMAC_SHA256",
            "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM",
            "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
            "ECIES_X25519_HKDF_HMAC_SHA256_AES128_GCM",
            "ECIES_X25519_HKDF_HMAC_SHA256_AES256_GCM",
            "ECIES_X25519_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
            "ECIES_X25519_HKDF_HMAC_SHA256_XCHACHA20_POLY1305",
            "ECIES_X25519_HKDF_HMAC_SHA256_DETERMINISTIC_AES_SIV",
            "HPKE_X25519_HKDF_SHA256_AES128_GCM",
            "HPKE_X25519_HKDF_SHA256_AES128_GCMRAW",
            "HPKE_X25519_HKDF_SHA256_AES256_GCM",
            "HPKE_X25519_HKDF_SHA256_AES256_GCM_RAW",
            "HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305",
            "HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305_RAW",
            nullptr
    };

    enum hybrid_key_templates {
        EciesP256HkdfHmacSha256Aes128Gcm,
        EciesP256HkdfHmacSha512Aes128Gcm,
        EciesP256HkdfHmacSha256Aes128GcmCompressedWithoutPrefix,
        EciesP256HkdfHmacSha256Aes128CtrHmacSha256,
        EciesP256HkdfHmacSha512Aes128CtrHmacSha256,
        EciesP256CompressedHkdfHmacSha256Aes128Gcm,
        EciesP256CompressedHkdfHmacSha256Aes128CtrHmacSha256,
        EciesX25519HkdfHmacSha256Aes128Gcm,
        EciesX25519HkdfHmacSha256Aes256Gcm,
        EciesX25519HkdfHmacSha256Aes128CtrHmacSha256,
        EciesX25519HkdfHmacSha256XChaCha20Poly1305,
        EciesX25519HkdfHmacSha256DeterministicAesSiv,
        HpkeX25519HkdfSha256Aes128Gcm,
        HpkeX25519HkdfSha256Aes128GcmRaw,
        HpkeX25519HkdfSha256Aes256Gcm,
        HpkeX25519HkdfSha256Aes256GcmRaw,
        HpkeX25519HkdfSha256ChaCha20Poly1305,
        HpkeX25519HkdfSha256ChaCha20Poly1305Raw
    };

    int key_template_index;
    if (TCL_OK !=
        Tcl_GetIndexFromObj(interp, objv[1], hybrid_key_template_names, "hybrid key template", 0,
                            &key_template_index)) {
        SetResult("Unknown hybrid key template");
        return TCL_ERROR;
    }

    KeyTemplate key_template;
    switch ((enum hybrid_key_templates) key_template_index) {
        case EciesP256HkdfHmacSha256Aes128Gcm:
            key_template = HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm();
            break;
        case EciesP256HkdfHmacSha512Aes128Gcm:
            key_template = HybridKeyTemplates::EciesP256HkdfHmacSha512Aes128Gcm();
            break;
        case EciesP256HkdfHmacSha256Aes128GcmCompressedWithoutPrefix:
            key_template = HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128GcmCompressedWithoutPrefix();
            break;
        case EciesP256HkdfHmacSha256Aes128CtrHmacSha256:
            key_template = HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128CtrHmacSha256();
            break;
        case EciesP256HkdfHmacSha512Aes128CtrHmacSha256:
            key_template = HybridKeyTemplates::EciesP256HkdfHmacSha512Aes128CtrHmacSha256();
            break;
        case EciesP256CompressedHkdfHmacSha256Aes128Gcm:
            key_template = HybridKeyTemplates::EciesP256CompressedHkdfHmacSha256Aes128Gcm();
            break;
        case EciesP256CompressedHkdfHmacSha256Aes128CtrHmacSha256:
            key_template = HybridKeyTemplates::EciesP256CompressedHkdfHmacSha256Aes128CtrHmacSha256();
            break;
        case EciesX25519HkdfHmacSha256Aes128Gcm:
            key_template = HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128Gcm();
            break;
        case EciesX25519HkdfHmacSha256Aes256Gcm:
            key_template = HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes256Gcm();
            break;
        case EciesX25519HkdfHmacSha256Aes128CtrHmacSha256:
            key_template = HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128CtrHmacSha256();
            break;
        case EciesX25519HkdfHmacSha256XChaCha20Poly1305:
            key_template = HybridKeyTemplates::EciesX25519HkdfHmacSha256XChaCha20Poly1305();
            break;
        case EciesX25519HkdfHmacSha256DeterministicAesSiv:
            key_template = HybridKeyTemplates::EciesX25519HkdfHmacSha256DeterministicAesSiv();
            break;
        case HpkeX25519HkdfSha256Aes128Gcm:
            key_template = HybridKeyTemplates::HpkeX25519HkdfSha256Aes128Gcm();
            break;
        case HpkeX25519HkdfSha256Aes128GcmRaw:
            key_template = HybridKeyTemplates::HpkeX25519HkdfSha256Aes128GcmRaw();
            break;
        case HpkeX25519HkdfSha256Aes256Gcm:
            key_template = HybridKeyTemplates::HpkeX25519HkdfSha256Aes256Gcm();
            break;
        case HpkeX25519HkdfSha256Aes256GcmRaw:
            key_template = HybridKeyTemplates::HpkeX25519HkdfSha256Aes256GcmRaw();
            break;
        case HpkeX25519HkdfSha256ChaCha20Poly1305:
            key_template = HybridKeyTemplates::HpkeX25519HkdfSha256ChaCha20Poly1305();
            break;
        case HpkeX25519HkdfSha256ChaCha20Poly1305Raw:
            key_template = HybridKeyTemplates::HpkeX25519HkdfSha256ChaCha20Poly1305Raw();
            break;
        default:
        SetResult("Unknown hybrid key template");
            return TCL_ERROR;
    }

    // This will generate a new keyset with only *one* key and return a keyset handle to it.
    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = KeysetHandle::GenerateNew(key_template);
    if (!keyset_handle.ok()) {
        SetResult("Error generating keyset");
        return TCL_ERROR;
    }

    std::stringbuf buffer;
    auto output_stream = absl::make_unique<std::ostream>(&buffer);

    absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> keyset_writer = JsonKeysetWriter::New(std::move(output_stream));
    if (!keyset_writer.ok()) {
        SetResult("Error creating writer");
        return TCL_ERROR;
    }

    absl::Status status = CleartextKeysetHandle::Write((keyset_writer)->get(), **keyset_handle);;
    if (!status.ok()) {
        SetResult("Error writing keyset");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewStringObj(buffer.str().c_str(), buffer.str().size()));
    return TCL_OK;
}

static int tink_SignatureSignCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "SignatureSignCmd\n"));
    CheckArgs(3, 3, 1, "keyset_handle content");

    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        SetResult("keyset handle not found");
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    auto valid = keyset_handle->Validate();
    if (!valid.ok()) {
        SetResult("error validating keyset");
        return TCL_ERROR;
    }

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<PublicKeySign>> public_key_sign_primitive = keyset_handle->GetPrimitive<PublicKeySign>();
    if (!public_key_sign_primitive.ok()) {
        SetResult("error getting primitive");
        return TCL_ERROR;
    }

    Tcl_Size content_length;
    const unsigned char *content = Tcl_GetByteArrayFromObj(objv[2], &content_length);
    absl::StatusOr<std::string> content_str = std::string((const char *) content, content_length);

    absl::StatusOr<std::string> signature =
            (*public_key_sign_primitive)->Sign(*content_str);

    if (!signature.ok()) {
        SetResult("error signing");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((const unsigned char *) signature.value().data(),
                                                 signature.value().size()));
    return TCL_OK;
}

static int tink_SignatureVerifyCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "SignatureVerifyCmd\n"));
    CheckArgs(4, 4, 1, "keyset_handle signature content");

    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        SetResult("keyset handle not found");
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    auto valid = keyset_handle->Validate();
    if (!valid.ok()) {
        SetResult("error validating keyset");
        return TCL_ERROR;
    }

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<PublicKeyVerify>> public_key_verify_primitive = keyset_handle->GetPrimitive<PublicKeyVerify>();
    if (!public_key_verify_primitive.ok()) {
        SetResult("error getting primitive");
        return TCL_ERROR;
    }

    Tcl_Size signature_length;
    const unsigned char *signature = Tcl_GetByteArrayFromObj(objv[2], &signature_length);
    absl::StatusOr<std::string> signature_str = std::string((const char *) signature, signature_length);

    Tcl_Size content_length;
    const unsigned char *content = Tcl_GetByteArrayFromObj(objv[3], &content_length);
    absl::StatusOr<std::string> content_str = std::string((const char *) content, content_length);

    absl::Status public_key_verify =
            (*public_key_verify_primitive)->Verify(*signature_str, *content_str);

    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(public_key_verify.ok()));
    return TCL_OK;
}

static int
tink_SignatureCreatePrivateKeysetCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "SignatureCreatePrivateKeysetCmd\n"));
    CheckArgs(2, 2, 1, "signature_key_template");

    static const char *signature_key_template_names[] = {
            "ECDSA_P256",
            "ECDSA_P384_SHA384",
            "ECDSA_P384_SHA512",
            "ECDSA_P521",
            "ECDSA_P256_RAW",
            "RSA_SSA_PKCS1_3072_SHA256_F4",
            "RSA_SSA_PKCS1_4096_SHA512_F4",
            "RSA_SSA_PSS_3072_SHA256_SHA256_F4",
            "RSA_SSA_PSS_4096_SHA512_SHA512_F4",
            "RSA_SSA_PSS_4096_SHA384_SHA384_F4",
            "ED25519",
            "ED25519_WITH_RAW_OUTPUT",
            nullptr
    };

    enum signature_key_templates {
        EcdsaP256,
        EcdsaP384Sha384,
        EcdsaP384Sha512,
        EcdsaP521,
        EcdsaP256Raw,
        RsaSsaPkcs13072Sha256F4,
        RsaSsaPkcs14096Sha512F4,
        RsaSsaPss3072Sha256Sha256F4,
        RsaSsaPss4096Sha512Sha512F4,
        RsaSsaPss4096Sha384Sha384F4,
        Ed25519,
        Ed25519WithRawOutput
    };

    int key_template_index;
    if (TCL_OK !=
        Tcl_GetIndexFromObj(interp, objv[1], signature_key_template_names, "signature key template", 0,
                            &key_template_index)) {
        SetResult("Unknown signature key template");
        return TCL_ERROR;
    }

    KeyTemplate key_template;
    switch ((enum signature_key_templates) key_template_index) {
        case EcdsaP256:
            key_template = SignatureKeyTemplates::EcdsaP256();
            break;
        case EcdsaP384Sha384:
            key_template = SignatureKeyTemplates::EcdsaP384Sha384();
            break;
        case EcdsaP384Sha512:
            key_template = SignatureKeyTemplates::EcdsaP384Sha512();
            break;
        case EcdsaP521:
            key_template = SignatureKeyTemplates::EcdsaP521();
            break;
        case EcdsaP256Raw:
            key_template = SignatureKeyTemplates::EcdsaP256Raw();
            break;
        case RsaSsaPkcs13072Sha256F4:
            key_template = SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4();
            break;
        case RsaSsaPkcs14096Sha512F4:
            key_template = SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4();
            break;
        case RsaSsaPss3072Sha256Sha256F4:
            key_template = SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4();
            break;
        case RsaSsaPss4096Sha512Sha512F4:
            key_template = SignatureKeyTemplates::RsaSsaPss4096Sha512Sha512F4();
            break;
        case RsaSsaPss4096Sha384Sha384F4:
            key_template = SignatureKeyTemplates::RsaSsaPss4096Sha384Sha384F4();
            break;
        case Ed25519:
            key_template = SignatureKeyTemplates::Ed25519();
            break;
        case Ed25519WithRawOutput:
            key_template = SignatureKeyTemplates::Ed25519WithRawOutput();
            break;
        default:
        SetResult("Unknown signature key template");
            return TCL_ERROR;
    }

    // This will generate a new keyset with only *one* key and return a keyset handle to it.
    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = KeysetHandle::GenerateNew(key_template);
    if (!keyset_handle.ok()) {
        SetResult("Error generating keyset");
        return TCL_ERROR;
    }

    std::stringbuf buffer;
    auto output_stream = absl::make_unique<std::ostream>(&buffer);

    absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> keyset_writer = JsonKeysetWriter::New(std::move(output_stream));
    if (!keyset_writer.ok()) {
        SetResult("Error creating writer");
        return TCL_ERROR;
    }

    absl::Status status = CleartextKeysetHandle::Write((keyset_writer)->get(), **keyset_handle);;
    if (!status.ok()) {
        SetResult("Error writing keyset");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewStringObj(buffer.str().c_str(), buffer.str().size()));
    return TCL_OK;
}

static int tink_DeterministicAeadEncryptCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "DeterministicAeadEncryptCmd\n"));
    CheckArgs(3, 4, 1, "keyset_handle plaintext ?associated_data?");

    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        SetResult("keyset handle not found");
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    auto valid = keyset_handle->Validate();
    if (!valid.ok()) {
        SetResult("error validating keyset");
        return TCL_ERROR;
    }

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<DeterministicAead>> daead_primitive = keyset_handle->GetPrimitive<DeterministicAead>();
    if (!daead_primitive.ok()) {
        SetResult("error getting primitive");
        return TCL_ERROR;
    }

    Tcl_Size plaintext_length;
    const unsigned char *plaintext = Tcl_GetByteArrayFromObj(objv[2], &plaintext_length);
    absl::StatusOr<std::string> plaintext_str = std::string((const char *) plaintext, plaintext_length);

    Tcl_Size associated_data_length;
    auto associated_data = (objc == 4) ? Tcl_GetByteArrayFromObj(objv[3], &associated_data_length) : nullptr;
    absl::string_view associated_data_str = (objc == 4) ? absl::string_view((const char *) associated_data,
                                                                            associated_data_length) : "";

    absl::StatusOr<std::string> encrypt_result =
            (*daead_primitive)->EncryptDeterministically(*plaintext_str, associated_data_str);

    if (!encrypt_result.ok()) {
        SetResult("error encrypting");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((const unsigned char *) encrypt_result.value().data(),
                                                 encrypt_result.value().size()));
    return TCL_OK;
}

static int tink_DeterministicAeadDecryptCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "DeterministicAeadDecryptCmd\n"));
    CheckArgs(3, 4, 1, "keyset_handle ciphertext ?associated_data?");

    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        SetResult("keyset handle not found");
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<DeterministicAead>> daead_primitive = keyset_handle->GetPrimitive<DeterministicAead>();
    if (!daead_primitive.ok()) {
        SetResult("error getting primitive");
        return TCL_ERROR;
    }

    Tcl_Size ciphertext_length;
    const unsigned char *ciphertext = Tcl_GetByteArrayFromObj(objv[2], &ciphertext_length);
    absl::StatusOr<std::string> ciphertext_str = std::string((const char *) ciphertext, ciphertext_length);

    Tcl_Size associated_data_length;
    auto associated_data = (objc == 4) ? Tcl_GetByteArrayFromObj(objv[3], &associated_data_length) : nullptr;
    absl::string_view associated_data_str = (objc == 4) ? absl::string_view((const char *) associated_data,
                                                                            associated_data_length) : "";
    absl::StatusOr<std::string> decrypt_result =
            (*daead_primitive)->DecryptDeterministically(*ciphertext_str, associated_data_str);

    if (!decrypt_result.ok()) {
        SetResult("error decrypting");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((const unsigned char *) decrypt_result.value().data(),
                                                 decrypt_result.value().size()));
    return TCL_OK;
}

static int tink_DaeadCreateKeysetCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "DaeadCreateKeysetCmd\n"));
    CheckArgs(2, 2, 1, "deterministic_aead_key_template");

    static const char *daead_key_template_names[] = {
            "AES256_SIV",
            nullptr
    };

    enum daead_key_templates {
        Aes256Siv
    };

    int key_template_index;
    if (TCL_OK !=
        Tcl_GetIndexFromObj(interp, objv[1], daead_key_template_names, "daead key template", 0, &key_template_index)) {
        SetResult("Unknown daead key template");
        return TCL_ERROR;
    }

    KeyTemplate key_template;
    switch ((enum daead_key_templates) key_template_index) {
        case Aes256Siv:
            key_template = DeterministicAeadKeyTemplates::Aes256Siv();
            break;
        default:
        SetResult("Unknown deterministic aead key template");
            return TCL_ERROR;
    }

    // This will generate a new keyset with only *one* key and return a keyset handle to it.
    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = KeysetHandle::GenerateNew(key_template);
    if (!keyset_handle.ok()) {
        SetResult("Error generating keyset");
        return TCL_ERROR;
    }

    std::stringbuf buffer;
    auto output_stream = absl::make_unique<std::ostream>(&buffer);

    absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> keyset_writer = JsonKeysetWriter::New(std::move(output_stream));
    if (!keyset_writer.ok()) {
        SetResult("Error creating writer");
        return TCL_ERROR;
    }

    absl::Status status = CleartextKeysetHandle::Write((keyset_writer)->get(), **keyset_handle);;
    if (!status.ok()) {
        SetResult("Error writing keyset");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewStringObj(buffer.str().c_str(), buffer.str().size()));
    return TCL_OK;
}

static int tink_JwtSignAndEncodeCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "JwtSignAndEncodeCmd\n"));
    CheckArgs(3, 3, 1, "keyset_handle jwt_dict");

    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        SetResult("keyset handle not found");
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    auto valid = keyset_handle->Validate();
    if (!valid.ok()) {
        SetResult("error validating keyset");
        return TCL_ERROR;
    }

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_signer = keyset_handle->GetPrimitive<JwtPublicKeySign>();
    if (!jwt_signer.ok()) {
        SetResult("error getting primitive");
        return TCL_ERROR;
    }

    RawJwtBuilder builder = RawJwtBuilder();

    Tcl_Obj *audiencePtr;
    Tcl_Obj *audienceKeyPtr = Tcl_NewStringObj("audience", -1);
    Tcl_IncrRefCount(audienceKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[2], audienceKeyPtr, &audiencePtr)) {
        Tcl_DecrRefCount(audienceKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(audienceKeyPtr);

    if (audiencePtr) {
        Tcl_Size audience_length;
        const char *audience = Tcl_GetStringFromObj(audiencePtr, &audience_length);
        builder.SetAudience(audience);
    }

    Tcl_Obj *expirySecondsPtr;
    Tcl_Obj *expirySecondsKeyPtr = Tcl_NewStringObj("expirySeconds", -1);
    Tcl_IncrRefCount(expirySecondsKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[2], expirySecondsKeyPtr, &expirySecondsPtr)) {
        Tcl_DecrRefCount(expirySecondsKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(expirySecondsKeyPtr);

    if (expirySecondsPtr) {
        long expirySeconds;
        if (TCL_OK != Tcl_GetLongFromObj(interp, expirySecondsPtr, &expirySeconds) || expirySeconds < 0) {
            SetResult("expiry seconds must be a long integer >= 0");
            return TCL_ERROR;
        }
        builder.SetExpiration(absl::Now() + absl::Seconds(expirySeconds));
    }

    Tcl_Obj *issuerPtr;
    Tcl_Obj *issuerKeyPtr = Tcl_NewStringObj("issuer", -1);
    Tcl_IncrRefCount(issuerKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[2], issuerKeyPtr, &issuerPtr)) {
        Tcl_DecrRefCount(issuerKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(issuerKeyPtr);

    if (issuerPtr) {
        Tcl_Size issuer_length;
        const char *issuer = Tcl_GetStringFromObj(issuerPtr, &issuer_length);
        builder.SetIssuer(issuer);
    }

    Tcl_Obj *subjectPtr;
    Tcl_Obj *subjectKeyPtr = Tcl_NewStringObj("subject", -1);
    Tcl_IncrRefCount(subjectKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[2], subjectKeyPtr, &subjectPtr)) {
        Tcl_DecrRefCount(subjectKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(subjectKeyPtr);

    if (subjectPtr) {
        Tcl_Size subject_length;
        const char *subject = Tcl_GetStringFromObj(subjectPtr, &subject_length);
        builder.SetSubject(subject);
    }

    Tcl_Obj *jwtIdPtr;
    Tcl_Obj *jwtIdKeyPtr = Tcl_NewStringObj("jwt_id", -1);
    Tcl_IncrRefCount(jwtIdKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[2], jwtIdKeyPtr, &jwtIdPtr)) {
        Tcl_DecrRefCount(jwtIdKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(jwtIdKeyPtr);

    if (jwtIdPtr) {
        Tcl_Size jwtId_length;
        const char *jwtId = Tcl_GetStringFromObj(jwtIdPtr, &jwtId_length);
        builder.SetJwtId(jwtId);
    }


    Tcl_Obj *claimsPtr;
    Tcl_Obj *claimsKeyPtr = Tcl_NewStringObj("claims", -1);
    Tcl_IncrRefCount(claimsKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[2], claimsKeyPtr, &claimsPtr)) {
        Tcl_DecrRefCount(claimsKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(claimsKeyPtr);

    if (claimsPtr) {
        Tcl_Size claims_length;
        if (TCL_OK != Tcl_ListObjLength(interp, claimsPtr, &claims_length) || claims_length % 2 != 0) {
            SetResult("error reading claims, list length must be even");
            return TCL_ERROR;
        }

        for (int i = 0; i < claims_length; i += 2) {
            Tcl_Obj *keyPtr;
            Tcl_Obj *valuePtr;
            if (TCL_OK != Tcl_ListObjIndex(interp, claimsPtr, i, &keyPtr) ||
                TCL_OK != Tcl_ListObjIndex(interp, claimsPtr, i + 1, &valuePtr)) {
                SetResult("error reading claims");
                return TCL_ERROR;
            }

            Tcl_Size key_length;
            const char *key = Tcl_GetStringFromObj(keyPtr, &key_length);

            Tcl_Size value_length;
            const char *value = Tcl_GetStringFromObj(valuePtr, &value_length);

            builder.AddStringClaim(key, value);
        }
    }

    absl::StatusOr<RawJwt> raw_jwt = builder.Build();

    absl::StatusOr<std::string> token =
            (*jwt_signer)->SignAndEncode(*raw_jwt);

    if (!token.ok()) {
        SetResult("error signing");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((const unsigned char *) token.value().data(),
                                                 token.value().size()));
    return TCL_OK;
}

static int tink_JwtVerifyAndDecodeCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "JwtVerifyAndDecodeCmd\n"));
    CheckArgs(4, 5, 1, "keyset_handle token validator_dict ?payload_varname?");

    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        SetResult("keyset handle not found");
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    auto valid = keyset_handle->Validate();
    if (!valid.ok()) {
        SetResult("error validating keyset");
        return TCL_ERROR;
    }

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verifier = keyset_handle->GetPrimitive<JwtPublicKeyVerify>();
    if (!jwt_verifier.ok()) {
        SetResult("error getting primitive");
        return TCL_ERROR;
    }

    Tcl_Size token_length;
    const unsigned char *token = Tcl_GetByteArrayFromObj(objv[2], &token_length);
    absl::StatusOr<std::string> token_str = std::string((const char *) token, token_length);

    JwtValidatorBuilder builder = JwtValidatorBuilder();

    Tcl_Obj *audiencePtr;
    Tcl_Obj *audienceKeyPtr = Tcl_NewStringObj("audience", -1);
    Tcl_IncrRefCount(audienceKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[3], audienceKeyPtr, &audiencePtr)) {
        Tcl_DecrRefCount(audienceKeyPtr);
        SetResult("invalid validator_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(audienceKeyPtr);

    if (audiencePtr) {
        Tcl_Size audience_length;
        const char *audience = Tcl_GetStringFromObj(audiencePtr, &audience_length);
        builder.ExpectAudience(audience);
    }

    Tcl_Obj *issuerPtr;
    Tcl_Obj *issuerKeyPtr = Tcl_NewStringObj("issuer", -1);
    Tcl_IncrRefCount(issuerKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[3], issuerKeyPtr, &issuerPtr)) {
        Tcl_DecrRefCount(issuerKeyPtr);
        SetResult("invalid validator_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(issuerKeyPtr);

    if (issuerPtr) {
        Tcl_Size issuer_length;
        const char *issuer = Tcl_GetStringFromObj(issuerPtr, &issuer_length);
        builder.ExpectIssuer(issuer);
    }

    absl::StatusOr<JwtValidator> validator = builder.Build();

    if (!validator.ok()) {
        SetResult("error creating validator");
        return TCL_ERROR;
    }

    absl::StatusOr<VerifiedJwt> verified_jwt =
            (*jwt_verifier)->VerifyAndDecode(*token_str, *validator);

    if (verified_jwt.ok() && objc == 5) {
        Tcl_Size varname_length;
        const char *varname = Tcl_GetStringFromObj(objv[4], &varname_length);

        Tcl_Obj *dictPtr = Tcl_NewDictObj();
        absl::StatusOr<std::string> payload = verified_jwt->GetJsonPayload();
        if (!payload.ok()) {
            SetResult("error getting payload");
            return TCL_ERROR;
        }
        Tcl_SetVar2(interp, varname, NULL, payload.value().c_str(), 0);
    }

    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(verified_jwt.ok()));
    return TCL_OK;
}

static int tink_JwkSetToPublicKeysetCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "JwkSetToPublicKeysetCmd\n"));
    CheckArgs(2, 2, 1, "jwk_set");

    Tcl_Size jwk_set_length;
    absl::StatusOr<std::string> jwk_set = Tcl_GetStringFromObj(objv[1], &jwk_set_length);

    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      JwkSetToPublicKeysetHandle(*jwk_set);


    auto public_keyset_handle = (*keyset_handle)->GetPublicKeysetHandle();
    if (!public_keyset_handle.ok()) {
        SetResult("Error getting public keyset handle");
        return TCL_ERROR;
    }

    std::stringbuf buffer;
    auto output_stream = absl::make_unique<std::ostream>(&buffer);

    absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> keyset_writer = JsonKeysetWriter::New(std::move(output_stream));
    if (!keyset_writer.ok()) {
        SetResult("Error creating writer");
        return TCL_ERROR;
    }

    absl::Status status = CleartextKeysetHandle::Write((keyset_writer)->get(), **public_keyset_handle);;
    if (!status.ok()) {
        SetResult("Error writing keyset");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewStringObj(buffer.str().c_str(), buffer.str().size()));
    return TCL_OK;
}

static int tink_JwkSetFromPublicKeysetCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "tink_JwkSetFromPublicKeysetCmd\n"));
    CheckArgs(2, 2, 1, "public_keyset");

    absl::string_view keyset = Tcl_GetString(objv[1]);
    auto reader_result = JsonKeysetReader::New(keyset);
    if (!reader_result.ok()) {
        SetResult("Error creating reader");
        return TCL_ERROR;
    }

    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = CleartextKeysetHandle::Read(
            *std::move(reader_result));
    if (!keyset_handle.ok()) {
        SetResult("Error reading keyset_handle");
        return TCL_ERROR;
    }


    absl::StatusOr<std::string> public_jwk_set =
            JwkSetFromPublicKeysetHandle(**keyset_handle);
    if (!public_jwk_set.ok()) {
        SetResult("Error getting public keyset");
    }

    Tcl_SetObjResult(interp, Tcl_NewStringObj(public_jwk_set.value().c_str(), public_jwk_set.value().size()));
    return TCL_OK;
}

static int tink_JwtCreatePrivateKeysetCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "JwtCreateKeysetCmd\n"));
    CheckArgs(2, 2, 1, "jwt_key_template");

    static const char *jwt_key_template_names[] = {
            "HS256",
            "RAW_HS256",
            "HS384",
            "RAW_HS384",
            "HS512",
            "RAW_HS512",
            "ES256",
            "RAW_ES256",
            "ES384",
            "RAW_ES384",
            "ES512",
            "RAW_ES512",
            "RS256_2048_F4",
            "RAW_RS256_2048_F4",
            "RS256_3072_F4",
            "RAW_RS256_3072_F4",
            "RS384_3072_F4",
            "RAW_RS384_3072_F4",
            "RS512_4096_F4",
            "RAW_RS512_4096_F4",
            "PS256_2048_F4",
            "RAW_PS256_2048_F4",
            "PS256_3072_F4",
            "RAW_PS256_3072_F4",
            "PS384_3072_F4",
            "RAW_PS384_3072_F4",
            "PS512_4096_F4",
            "RAW_PS512_4096_F4",
            nullptr
    };

    enum jwt_key_templates {
        JwtHs256,
        RawJwtHs256,
        JwtHs384,
        RawJwtHs384,
        JwtHs512,
        RawJwtHs512,
        JwtEs256,
        RawJwtEs256,
        JwtEs384,
        RawJwtEs384,
        JwtEs512,
        RawJwtEs512,
        JwtRs256_2048_F4,
        RawJwtRs256_2048_F4,
        JwtRs256_3072_F4,
        RawJwtRs256_3072_F4,
        JwtRs384_3072_F4,
        RawJwtRs384_3072_F4,
        JwtRs512_4096_F4,
        RawJwtRs512_4096_F4,
        JwtPs256_2048_F4,
        RawJwtPs256_2048_F4,
        JwtPs256_3072_F4,
        RawJwtPs256_3072_F4,
        JwtPs384_3072_F4,
        RawJwtPs384_3072_F4,
        JwtPs512_4096_F4,
        RawJwtPs512_4096_F4
    };

    int key_template_index;
    if (TCL_OK !=
        Tcl_GetIndexFromObj(interp, objv[1], jwt_key_template_names, "jwt key template", 0, &key_template_index)) {
        SetResult("Unknown jwt key template");
        return TCL_ERROR;
    }

    KeyTemplate key_template;
    switch ((enum jwt_key_templates) key_template_index) {
        case JwtHs256:
            key_template = ::crypto::tink::JwtHs256Template();
            break;
        case RawJwtHs256:
            key_template = ::crypto::tink::RawJwtHs256Template();
            break;
        case JwtHs384:
            key_template = ::crypto::tink::JwtHs384Template();
            break;
        case RawJwtHs384:
            key_template = ::crypto::tink::RawJwtHs384Template();
            break;
        case JwtHs512:
            key_template = ::crypto::tink::JwtHs512Template();
            break;
        case RawJwtHs512:
            key_template = ::crypto::tink::RawJwtHs512Template();
            break;
        case JwtEs256:
            key_template = ::crypto::tink::JwtEs256Template();
            break;
        case RawJwtEs256:
            key_template = ::crypto::tink::RawJwtEs256Template();
            break;
        case JwtEs384:
            key_template = ::crypto::tink::JwtEs384Template();
            break;
        case RawJwtEs384:
            key_template = ::crypto::tink::RawJwtEs384Template();
            break;
        case JwtEs512:
            key_template = ::crypto::tink::JwtEs512Template();
            break;
        case RawJwtEs512:
            key_template = ::crypto::tink::RawJwtEs512Template();
            break;
        case JwtRs256_2048_F4:
            key_template = ::crypto::tink::JwtRs256_2048_F4_Template();
            break;
        case RawJwtRs256_2048_F4:
            key_template = ::crypto::tink::RawJwtRs256_2048_F4_Template();
            break;
        case JwtRs256_3072_F4:
            key_template = ::crypto::tink::JwtRs256_3072_F4_Template();
            break;
        case RawJwtRs256_3072_F4:
            key_template = ::crypto::tink::RawJwtRs256_3072_F4_Template();
            break;
        case JwtRs384_3072_F4:
            key_template = ::crypto::tink::JwtRs384_3072_F4_Template();
            break;
        case RawJwtRs384_3072_F4:
            key_template = ::crypto::tink::RawJwtRs384_3072_F4_Template();
            break;
        case JwtRs512_4096_F4:
            key_template = ::crypto::tink::JwtRs512_4096_F4_Template();
            break;
        case RawJwtRs512_4096_F4:
            key_template = ::crypto::tink::RawJwtRs512_4096_F4_Template();
            break;
        case JwtPs256_2048_F4:
            key_template = ::crypto::tink::JwtPs256_2048_F4_Template();
            break;
        case RawJwtPs256_2048_F4:
            key_template = ::crypto::tink::RawJwtPs256_2048_F4_Template();
            break;
        case JwtPs256_3072_F4:
            key_template = ::crypto::tink::JwtPs256_3072_F4_Template();
            break;
        case RawJwtPs256_3072_F4:
            key_template = ::crypto::tink::RawJwtPs256_3072_F4_Template();
            break;
        case JwtPs384_3072_F4:
            key_template = ::crypto::tink::JwtPs384_3072_F4_Template();
            break;
        case RawJwtPs384_3072_F4:
            key_template = ::crypto::tink::RawJwtPs384_3072_F4_Template();
            break;
        case JwtPs512_4096_F4:
            key_template = ::crypto::tink::JwtPs512_4096_F4_Template();
            break;
        case RawJwtPs512_4096_F4:
            key_template = ::crypto::tink::RawJwtPs512_4096_F4_Template();
            break;
        default:
        SetResult("Unknown jwt key template");
            return TCL_ERROR;
    }

    // This will generate a new keyset with only *one* key and return a keyset handle to it.
    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = KeysetHandle::GenerateNew(key_template);
    if (!keyset_handle.ok()) {
        SetResult("Error generating keyset");
        return TCL_ERROR;
    }

    std::stringbuf buffer;
    auto output_stream = absl::make_unique<std::ostream>(&buffer);

    absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> keyset_writer = JsonKeysetWriter::New(std::move(output_stream));
    if (!keyset_writer.ok()) {
        SetResult("Error creating writer");
        return TCL_ERROR;
    }

    absl::Status status = CleartextKeysetHandle::Write((keyset_writer)->get(), **keyset_handle);;
    if (!status.ok()) {
        SetResult("Error writing keyset");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewStringObj(buffer.str().c_str(), buffer.str().size()));
    return TCL_OK;
}

static void tink_ExitHandler(ClientData unused) {
    Tcl_MutexLock(&tink_KeysetNameToInternal_HT_Mutex);
    Tcl_DeleteHashTable(&tink_KeysetNameToInternal_HT);
    Tcl_MutexUnlock(&tink_KeysetNameToInternal_HT_Mutex);
}

void tink_InitModule() {
    if (!tink_ModuleInitialized) {
        auto status = TinkConfig::Register();
        if (!status.ok()) {
            std::cerr << "TinkConfig::Register() failed " << std::endl;
        }

        auto jwt_status = JwtSignatureRegister();
        if (!jwt_status.ok()) {
            std::cerr << "JwtSignatureRegister() failed " << std::endl;
        }

        auto jwt_mac_status = JwtMacRegister();
        if (!jwt_mac_status.ok()) {
            std::cerr << "JwtMacRegister() failed " << std::endl;
        }

        Tcl_MutexLock(&tink_KeysetNameToInternal_HT_Mutex);
        Tcl_InitHashTable(&tink_KeysetNameToInternal_HT, TCL_STRING_KEYS);
        Tcl_MutexUnlock(&tink_KeysetNameToInternal_HT_Mutex);

        Tcl_CreateExitHandler(tink_ExitHandler, nullptr);
        tink_ModuleInitialized = 1;
    }
}

int Tink_Init(Tcl_Interp *interp) {
    if (Tcl_InitStubs(interp, "8.6", 0) == nullptr) {
        return TCL_ERROR;
    }

    tink_InitModule();


    Tcl_CreateNamespace(interp, "::tink", nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::register_keyset", tink_RegisterKeysetCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::unregister_keyset", tink_UnregisterKeysetCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::create_public_keyset", tink_CreatePublicKeysetCmd, nullptr, nullptr);

    Tcl_CreateNamespace(interp, "::tink::aead", nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::aead::encrypt", tink_AeadEncryptCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::aead::decrypt", tink_AeadDecryptCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::aead::create_keyset", tink_AeadCreateKeysetCmd, nullptr, nullptr);

    Tcl_CreateNamespace(interp, "::tink::mac", nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::mac::compute", tink_MacComputeCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::mac::verify", tink_MacVerifyCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::mac::create_keyset", tink_MacCreateKeysetCmd, nullptr, nullptr);

    Tcl_CreateNamespace(interp, "::tink::hybrid", nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::hybrid::encrypt", tink_HybridEncryptCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::hybrid::decrypt", tink_HybridDecryptCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::hybrid::create_private_keyset", tink_HybridCreatePrivateKeysetCmd, nullptr,
                         nullptr);

    Tcl_CreateNamespace(interp, "::tink::signature", nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::signature::sign", tink_SignatureSignCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::signature::verify", tink_SignatureVerifyCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::signature::create_private_keyset", tink_SignatureCreatePrivateKeysetCmd,
                         nullptr, nullptr);

    Tcl_CreateNamespace(interp, "::tink::daead", nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::daead::encrypt_deterministically", tink_DeterministicAeadEncryptCmd, nullptr,
                         nullptr);
    Tcl_CreateObjCommand(interp, "::tink::daead::decrypt_deterministically", tink_DeterministicAeadDecryptCmd, nullptr,
                         nullptr);
    Tcl_CreateObjCommand(interp, "::tink::daead::create_keyset", tink_DaeadCreateKeysetCmd, nullptr, nullptr);

    Tcl_CreateNamespace(interp, "::tink::jwt", nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::jwt::sign_and_encode", tink_JwtSignAndEncodeCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::jwt::verify_and_decode", tink_JwtVerifyAndDecodeCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::jwt::jwk_set_to_public_keyset", tink_JwkSetToPublicKeysetCmd, nullptr,
                         nullptr);
    Tcl_CreateObjCommand(interp, "::tink::jwt::jwk_set_from_public_keyset", tink_JwkSetFromPublicKeysetCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::jwt::create_private_keyset", tink_JwtCreatePrivateKeysetCmd, nullptr, nullptr);

    return Tcl_PkgProvide(interp, "tink", XSTR(PROJECT_VERSION));
}

#ifdef USE_NAVISERVER
int Ns_ModuleInit(const char *server, const char *module) {
    Ns_TclRegisterTrace(server, (Ns_TclTraceProc *) Tink_Init, server, NS_TCL_TRACE_CREATE);
    return NS_OK;
}
#endif
