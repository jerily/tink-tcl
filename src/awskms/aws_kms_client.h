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

#ifndef TINK_INTEGRATION_AWSKMS_AWS_KMS_CLIENT_H_
#define TINK_INTEGRATION_AWSKMS_AWS_KMS_CLIENT_H_

#include <memory>
#include <tcl.h>

#include "aws/core/auth/AWSCredentialsProvider.h"
#include "aws/kms/KMSClient.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "tink/aead.h"
#include "tink/kms_client.h"
#include "tink/kms_clients.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"


namespace crypto::tink::integration::awskms {

// AwsKmsClient is an implementation of KmsClient for AWS KMS
// (https://aws.amazon.com/kms/).
    class AwsKmsClient : public crypto::tink::KmsClient {
    public:
        // Move only.
        AwsKmsClient(AwsKmsClient &&other) = default;

        AwsKmsClient &operator=(AwsKmsClient &&other) = default;

        AwsKmsClient(const AwsKmsClient &) = delete;

        AwsKmsClient &operator=(const AwsKmsClient &) = delete;

        // Creates a new AwsKmsClient that is bound to the key specified in `key_uri`,
        // if not empty, and that uses the credentials in `credentials_path`, if not
        // empty, or the default ones to authenticate to the KMS.
        //
        // If `key_uri` is empty, then the client is not bound to any particular key.
        static crypto::tink::util::StatusOr<std::unique_ptr<AwsKmsClient>> New(
                Tcl_Interp *interp,
                absl::string_view key_uri, Tcl_Obj *configDictPtr);

        // Creates a new client and registers it in KMSClients.
        static crypto::tink::util::Status RegisterNewClient(
                Tcl_Interp *interp,
                absl::string_view key_uri, Tcl_Obj *dictPtr);

        // Returns true if: (1) `key_uri` is a valid AWS KMS key URI, and (2) the
        // resulting AWS key ARN is equals to key_arn_, in case this client is bound
        // to a specific key.
        bool DoesSupport(absl::string_view key_uri) const override;

        crypto::tink::util::StatusOr<std::unique_ptr<Aead>> GetAead(
                absl::string_view key_uri) const override;

    private:
        AwsKmsClient(Tcl_Interp *interp, absl::string_view key_arn, Tcl_Obj *configDictPtr)
                : key_arn_(key_arn), interp_(interp), configDictPtr_(configDictPtr) {}

        std::string key_arn_;
        Tcl_Interp *interp_;
        Tcl_Obj *configDictPtr_;
        std::shared_ptr<Aws::KMS::KMSClient> aws_client_;
    };

} // namespace crypto::tink::integration::awskms




#endif  // TINK_INTEGRATION_AWSKMS_AWS_KMS_CLIENT_H_