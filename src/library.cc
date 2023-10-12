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

using crypto::tink::TinkConfig;
using crypto::tink::JsonKeysetReader;
using crypto::tink::JsonKeysetWriter;
using crypto::tink::CleartextKeysetHandle;
using crypto::tink::KeysetHandle;
using crypto::tink::Aead;
using crypto::tink::AeadKeyTemplates;
using google::crypto::tink::KeyTemplate;

static int tink_ModuleInitialized;

static int tink_AeadEncryptCmd(ClientData  clientData, Tcl_Interp *interp, int objc, Tcl_Obj * const objv[] ) {
    DBG(fprintf(stderr, "AeadEncryptCmd\n"));
    CheckArgs(3, 4, 1, "keyset plaintext ?associated_data?");

    absl::string_view keyset = Tcl_GetString(objv[1]);
    auto reader_result = JsonKeysetReader::New(keyset);
    if (!reader_result.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error reading keyset", -1));
        return TCL_ERROR;
    }

    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = CleartextKeysetHandle::Read(*std::move(reader_result));
    if (!keyset_handle.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error reading keyset_handle", -1));
        return TCL_ERROR;
    }

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<Aead>> aead = (*keyset_handle)->GetPrimitive<Aead>();
    if (!aead.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error getting primitive", -1));
        return TCL_ERROR;
    }

    int plaintext_length;
    const unsigned char *plaintext = Tcl_GetByteArrayFromObj(objv[2], &plaintext_length);
    absl::StatusOr<std::string> plaintext_str = std::string((const char *) plaintext, plaintext_length);

    int associated_data_length;
    auto associated_data = (objc == 4) ? Tcl_GetByteArrayFromObj(objv[3], &associated_data_length) : nullptr;
    absl::string_view associated_data_str = (objc == 4) ? absl::string_view((const char *) associated_data, associated_data_length) : "";

    absl::StatusOr<std::string> encrypt_result =
            (*aead)->Encrypt(*plaintext_str, associated_data_str);

    if (!encrypt_result.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error encrypting", -1));
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((const unsigned char *) encrypt_result.value().data(), encrypt_result.value().size()));
    return TCL_OK;
}

static int tink_AeadDecryptCmd(ClientData  clientData, Tcl_Interp *interp, int objc, Tcl_Obj * const objv[] ) {
    DBG(fprintf(stderr, "AeadDecryptCmd\n"));
    CheckArgs(3, 4, 1, "keyset ciphertext ?associated_data?");

    absl::string_view keyset = Tcl_GetString(objv[1]);
    auto reader_result = JsonKeysetReader::New(keyset);
    if (!reader_result.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error reading keyset", -1));
        return TCL_ERROR;
    }

    absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle = CleartextKeysetHandle::Read(*std::move(reader_result));
    if (!keyset_handle.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error reading keyset_handle", -1));
        return TCL_ERROR;
    }

    if (!keyset_handle.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error reading keyset_handle", -1));
        return TCL_ERROR;
    }

    // Get the primitive.
    absl::StatusOr<std::unique_ptr<Aead>> aead = (*keyset_handle)->GetPrimitive<Aead>();
    if (!aead.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error getting primitive", -1));
        return TCL_ERROR;
    }

    int ciphertext_length;
    const unsigned char *ciphertext = Tcl_GetByteArrayFromObj(objv[2], &ciphertext_length);
    absl::StatusOr<std::string> ciphertext_str = std::string((const char *) ciphertext, ciphertext_length);

    int associated_data_length;
    auto associated_data = (objc == 4) ? Tcl_GetByteArrayFromObj(objv[3], &associated_data_length) : nullptr;
    absl::string_view associated_data_str = (objc == 4) ? absl::string_view((const char *) associated_data, associated_data_length) : "";
    absl::StatusOr<std::string> decrypt_result =
            (*aead)->Decrypt(*ciphertext_str, associated_data_str);

    if (!decrypt_result.ok()) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error decrypting", -1));
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((const unsigned char *) decrypt_result.value().data(), decrypt_result.value().size()));
    return TCL_OK;
}

static int tink_AeadCreateKeysetCmd(ClientData  clientData, Tcl_Interp *interp, int objc, Tcl_Obj * const objv[] ) {
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
    if (TCL_OK != Tcl_GetIndexFromObj(interp, objv[1], aead_key_template_names, "aead key template", 0, &key_template_index)) {
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

static void tink_ExitHandler(ClientData unused) {
}


void tink_InitModule() {
    if (!tink_ModuleInitialized) {
        auto status = TinkConfig::Register();
        if (!status.ok()) {
            std::cerr << "TinkConfig::Register() failed " << std::endl;
        }

        Tcl_CreateThreadExitHandler(tink_ExitHandler, nullptr);
        tink_ModuleInitialized = 1;
    }
}

int Tink_Init(Tcl_Interp *interp) {
    if (Tcl_InitStubs(interp, "8.6", 0) == nullptr) {
        return TCL_ERROR;
    }

    tink_InitModule();

    Tcl_CreateNamespace(interp, "::tink::aead", nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::aead::encrypt", tink_AeadEncryptCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::aead::decrypt", tink_AeadDecryptCmd, nullptr, nullptr);
    Tcl_CreateObjCommand(interp, "::tink::aead::create_keyset", tink_AeadCreateKeysetCmd, nullptr, nullptr);

    return Tcl_PkgProvide(interp, "tink", XSTR(PROJECT_VERSION));
}

#ifdef USE_NAVISERVER
int Ns_ModuleInit(const char *server, const char *module) {
    Ns_TclRegisterTrace(server, (Ns_TclTraceProc *) Tink_Init, server, NS_TCL_TRACE_CREATE);
    return NS_OK;
}
#endif
