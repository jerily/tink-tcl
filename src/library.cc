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
#include <tink/aead/aead_key_templates.h>
#include <tink/mac.h>
#include <tink/mac/mac_key_templates.h>
#include "library.h"

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
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error reading keyset", -1));
        return TCL_ERROR;
    }

    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = CleartextKeysetHandle::Read(
            *std::move(reader_result));
    if (!keyset_handle.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error reading keyset_handle", -1));
        return TCL_ERROR;
    }

    auto keyset_ptr = (tink_keyset_t *) Tcl_Alloc(sizeof(tink_keyset_t));
    if (keyset_ptr == nullptr) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error allocating memory", -1));
        return TCL_ERROR;
    }
    keyset_ptr->keyset_handle = (*keyset_handle).release();
    char keyset_name[40];
    CMD_KEYSET_NAME(keyset_name, keyset_ptr->keyset_handle);
    fprintf(stderr, "keyset_name=%s\n", keyset_name);
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
        Tcl_SetObjResult(interp, Tcl_NewStringObj("keyset handle not found", -1));
        return TCL_ERROR;
    }
    tink_UnregisterKeysetName(keyset_name);
    delete keyset_ptr->keyset_handle;
    Tcl_Free((char *) keyset_ptr);
    return TCL_OK;
}

static int tink_AeadEncryptCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AeadEncryptCmd\n"));
    CheckArgs(3, 4, 1, "keyset_handle plaintext ?associated_data?");

    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("keyset handle not found", -1));
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    auto valid = keyset_handle->Validate();
    if (!valid.ok()) {
        SetResult("error validating keyset");
        return TCL_ERROR;
    }

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<Aead>> aead = keyset_handle->GetPrimitive<Aead>();
    if (!aead.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error getting primitive", -1));
        return TCL_ERROR;
    }

    int plaintext_length;
    const unsigned char *plaintext = Tcl_GetByteArrayFromObj(objv[2], &plaintext_length);
    absl::StatusOr<std::string> plaintext_str = std::string((const char *) plaintext, plaintext_length);

    int associated_data_length;
    auto associated_data = (objc == 4) ? Tcl_GetByteArrayFromObj(objv[3], &associated_data_length) : nullptr;
    absl::string_view associated_data_str = (objc == 4) ? absl::string_view((const char *) associated_data,
                                                                            associated_data_length) : "";

    absl::StatusOr<std::string> encrypt_result =
            (*aead)->Encrypt(*plaintext_str, associated_data_str);

    if (!encrypt_result.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error encrypting", -1));
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((const unsigned char *) encrypt_result.value().data(),
                                                 encrypt_result.value().size()));
    return TCL_OK;
}

static int tink_AeadDecryptCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AeadDecryptCmd\n"));
    CheckArgs(3, 4, 1, "keyset ciphertext ?associated_data?");

//    absl::string_view keyset = Tcl_GetString(objv[1]);
//    auto reader_result = JsonKeysetReader::New(keyset);
//    if (!reader_result.ok()) {
//        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error reading keyset", -1));
//        return TCL_ERROR;
//    }
//
//    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = CleartextKeysetHandle::Read(*std::move(reader_result));
//    if (!keyset_handle.ok()) {
//        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error reading keyset_handle", -1));
//        return TCL_ERROR;
//    }
//    if (!keyset_handle.ok()) {
//        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error reading keyset_handle", -1));
//        return TCL_ERROR;
//    }


    auto keyset_name = Tcl_GetString(objv[1]);
    auto keyset_ptr = tink_GetInternalFromKeysetName(keyset_name);
    if (keyset_ptr == nullptr) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("keyset handle not found", -1));
        return TCL_ERROR;
    }

    auto keyset_handle = keyset_ptr->keyset_handle;

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<Aead>> aead = keyset_handle->GetPrimitive<Aead>();
    if (!aead.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error getting primitive", -1));
        return TCL_ERROR;
    }

    int ciphertext_length;
    const unsigned char *ciphertext = Tcl_GetByteArrayFromObj(objv[2], &ciphertext_length);
    absl::StatusOr<std::string> ciphertext_str = std::string((const char *) ciphertext, ciphertext_length);

    int associated_data_length;
    auto associated_data = (objc == 4) ? Tcl_GetByteArrayFromObj(objv[3], &associated_data_length) : nullptr;
    absl::string_view associated_data_str = (objc == 4) ? absl::string_view((const char *) associated_data,
                                                                            associated_data_length) : "";
    absl::StatusOr<std::string> decrypt_result =
            (*aead)->Decrypt(*ciphertext_str, associated_data_str);

    if (!decrypt_result.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error decrypting", -1));
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
            "Aes128Eax",
            "Aes256Eax",
            "Aes128Gcm",
            "Aes128GcmNoPrefix",
            "Aes256Gcm",
            "Aes256GcmNoPrefix",
            "Aes128GcmSiv",
            "Aes256GcmSiv",
            "Aes128CtrHmacSha256",
            "Aes256CtrHmacSha256",
            "XChaCha20Poly1305",
            "KmsEnvelopeAead",
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
        XChaCha20Poly1305,
        KmsEnvelopeAead
    };

    int key_template_index;
    if (TCL_OK !=
        Tcl_GetIndexFromObj(interp, objv[1], aead_key_template_names, "aead key template", 0, &key_template_index)) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Unknown aead key template", -1));
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
        case KmsEnvelopeAead:
//            key_template = AeadKeyTemplates::KmsEnvelopeAead();
            break;
        default:
            Tcl_SetObjResult(interp, Tcl_NewStringObj("Unknown aead key template", -1));
            return TCL_ERROR;
    }

    // This will generate a new keyset with only *one* key and return a keyset handle to it.
    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = KeysetHandle::GenerateNew(key_template);
    if (!keyset_handle.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error generating keyset", -1));
        return TCL_ERROR;
    }

    std::stringbuf buffer;
    auto output_stream = absl::make_unique<std::ostream>(&buffer);

    absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> keyset_writer = JsonKeysetWriter::New(std::move(output_stream));
    if (!keyset_writer.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error creating writer", -1));
        return TCL_ERROR;
    }

    absl::Status status = CleartextKeysetHandle::Write((keyset_writer)->get(), **keyset_handle);;
    if (!status.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error writing keyset", -1));
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
        Tcl_SetObjResult(interp, Tcl_NewStringObj("keyset handle not found", -1));
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

    int content_length;
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
        Tcl_SetObjResult(interp, Tcl_NewStringObj("keyset handle not found", -1));
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

    int tag_length;
    const unsigned char *tag = Tcl_GetByteArrayFromObj(objv[2], &tag_length);
    std::string tag_str = std::string((const char *) tag, tag_length);

    int content_length;
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
            "HmacSha256HalfSizeTag",
            "HmacSha256",
            "HmacSha512HalfSizeTag",
            "HmacSha512",
            "AesCmac",
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
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Unknown mac key template", -1));
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
            Tcl_SetObjResult(interp, Tcl_NewStringObj("Unknown mac key template", -1));
            return TCL_ERROR;
    }

    // This will generate a new keyset with only *one* key and return a keyset handle to it.
    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = KeysetHandle::GenerateNew(key_template);
    if (!keyset_handle.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error generating keyset", -1));
        return TCL_ERROR;
    }

    std::stringbuf buffer;
    auto output_stream = absl::make_unique<std::ostream>(&buffer);

    absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> keyset_writer = JsonKeysetWriter::New(std::move(output_stream));
    if (!keyset_writer.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error creating writer", -1));
        return TCL_ERROR;
    }

    absl::Status status = CleartextKeysetHandle::Write((keyset_writer)->get(), **keyset_handle);;
    if (!status.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error writing keyset", -1));
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

        Tcl_MutexLock(&tink_KeysetNameToInternal_HT_Mutex);
        Tcl_InitHashTable(&tink_KeysetNameToInternal_HT, TCL_STRING_KEYS);
        Tcl_MutexUnlock(&tink_KeysetNameToInternal_HT_Mutex);

        Tcl_CreateThreadExitHandler(tink_ExitHandler, nullptr);
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

    Tcl_CreateNamespace(interp, "::tink::aead", nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::aead::encrypt", tink_AeadEncryptCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::aead::decrypt", tink_AeadDecryptCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::aead::create_keyset", tink_AeadCreateKeysetCmd, nullptr, nullptr);

    Tcl_CreateNamespace(interp, "::tink::mac", nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::mac::compute", tink_MacComputeCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::mac::verify", tink_MacVerifyCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::mac::create_keyset", tink_MacCreateKeysetCmd, nullptr, nullptr);

    return Tcl_PkgProvide(interp, "tink", XSTR(PROJECT_VERSION));
}

#ifdef USE_NAVISERVER
int Ns_ModuleInit(const char *server, const char *module) {
    Ns_TclRegisterTrace(server, (Ns_TclTraceProc *) Tink_Init, server, NS_TCL_TRACE_CREATE);
    return NS_OK;
}
#endif
