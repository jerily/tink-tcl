// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////
#include "aws_kms_client.h"

#include <fstream>
#include <iostream>
#include <sstream>

#include "aws/core/Aws.h"
#include "aws/core/auth/AWSCredentialsProvider.h"
#include "aws/core/auth/AWSCredentialsProviderChain.h"
#include "aws/core/client/ClientConfiguration.h"
#include "aws/core/utils/crypto/Factories.h"
#include "aws/core/utils/memory/AWSMemory.h"
#include "aws/kms/KMSClient.h"
#include "absl/base/call_once.h"
#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/match.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "aws_kms_aead.h"
#include "tink/kms_client.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"


namespace crypto::tink::integration::awskms {
    namespace {

        constexpr absl::string_view kKeyUriPrefix = "aws-kms://";
        constexpr char kTinkAwsKmsAllocationTag[] = "tink::integration::awskms";

// Returns AWS key ARN contained in `key_uri`. If `key_uri` does not refer to an
// AWS key, returns an error.
        util::StatusOr<std::string> GetKeyArn(absl::string_view key_uri) {
            if (!absl::StartsWithIgnoreCase(key_uri, kKeyUriPrefix)) {
                return util::Status(absl::StatusCode::kInvalidArgument,
                                    absl::StrCat("Invalid key URI ", key_uri));
            }
            return std::string(key_uri.substr(kKeyUriPrefix.length()));
        }

// Returns ClientConfiguration with region set to the value extracted from
// `key_arn`.
// An AWS key ARN is of the form
// arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab.
        util::StatusOr<Aws::Client::ClientConfiguration> GetAwsClientConfig(
                Tcl_Interp *interp,
                absl::string_view key_arn,
                Tcl_Obj *dictPtr
        ) {

            std::vector<std::string> key_arn_parts = absl::StrSplit(key_arn, ':');
            if (key_arn_parts.size() < 6) {
                return util::Status(absl::StatusCode::kInvalidArgument,
                                    absl::StrCat("Invalid key ARN ", key_arn));
            }

            Aws::Client::ClientConfiguration clientConfig;

            // 4th part of key arn.
            clientConfig.region = key_arn_parts[3];
            clientConfig.scheme = Aws::Http::Scheme::HTTPS;
            clientConfig.connectTimeoutMs = 30000;
            clientConfig.requestTimeoutMs = 60000;

            if (dictPtr != nullptr) {
                Tcl_Obj *region;
                Tcl_Obj *endpoint;
                Tcl_DictObjGet(interp, dictPtr, Tcl_NewStringObj("region", -1), &region);
                Tcl_DictObjGet(interp, dictPtr, Tcl_NewStringObj("endpoint", -1), &endpoint);
                if (region) {
                    clientConfig.region = Tcl_GetString(region);
                }
                if (endpoint) {
                    clientConfig.endpointOverride = Tcl_GetString(endpoint);
                }
            }
            return clientConfig;
        }

    }  // namespace

    util::StatusOr<std::unique_ptr<AwsKmsClient>> AwsKmsClient::New(
            Tcl_Interp *interp,
            absl::string_view key_uri,
            Tcl_Obj *configDictPtr
    ) {

        // If a specific key is given, create an AWS KMSClient.
        util::StatusOr<std::string> key_arn = GetKeyArn(key_uri);
        if (!key_arn.ok()) {
            return key_arn.status();
        }
        util::StatusOr<Aws::Client::ClientConfiguration> client_config =
                GetAwsClientConfig(interp, *key_arn, configDictPtr);
        if (!client_config.ok()) {
            return client_config.status();
        }
        auto client = absl::WrapUnique(new AwsKmsClient(interp, *key_arn, configDictPtr));
        // Create AWS KMSClient.
        client->aws_client_ = Aws::MakeShared<Aws::KMS::KMSClient>(kTinkAwsKmsAllocationTag, *client_config);
        return std::move(client);
    }

    bool AwsKmsClient::DoesSupport(absl::string_view key_uri) const {
        util::StatusOr<std::string> key_arn = GetKeyArn(key_uri);
        if (!key_arn.ok()) {
            return false;
        }
        // If this is bound to a specific key, make sure the key ARNs are equal.
        return key_arn_.empty() || key_arn_ == *key_arn;
    }

    util::StatusOr<std::unique_ptr<Aead>> AwsKmsClient::GetAead(
            absl::string_view key_uri) const {
        util::StatusOr<std::string> key_arn = GetKeyArn(key_uri);
        if (!key_arn.ok()) {
            return key_arn.status();
        }
        // This client is bound to a specific key.
        if (!key_arn_.empty()) {
            if (key_arn_ != *key_arn) {
                return util::Status(absl::StatusCode::kInvalidArgument,
                                    absl::StrCat("This client is bound to ", key_arn_,
                                                 " and cannot use key ", key_uri));
            }
            return AwsKmsAead::New(key_arn_, aws_client_);
        }

        util::StatusOr<Aws::Client::ClientConfiguration> client_config =
                GetAwsClientConfig(interp_, *key_arn, configDictPtr_);
        if (!client_config.ok()) {
            return client_config.status();
        }
        auto aws_client = Aws::MakeShared<Aws::KMS::KMSClient>(
                kTinkAwsKmsAllocationTag, *client_config);
        return AwsKmsAead::New(*key_arn, aws_client);
    }

    util::Status AwsKmsClient::RegisterNewClient(
            Tcl_Interp *interp,
            absl::string_view key_uri, Tcl_Obj *dictPtr) {
        util::StatusOr<std::unique_ptr<AwsKmsClient>> client_result =
                AwsKmsClient::New(interp, key_uri, dictPtr);
        if (!client_result.ok()) {
            return client_result.status();
        }

        return KmsClients::Add(*std::move(client_result));
    }

} // namespace crypto::tink::integration::awskms



