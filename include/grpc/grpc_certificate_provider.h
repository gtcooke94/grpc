//
//
// Copyright 2024 gRPC authors.
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
//

#ifndef GRPC_GRPC_CERTIFICATE_PROVIDER_H
#define GRPC_GRPC_CERTIFICATE_PROVIDER_H

#include <memory>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

#include <grpc/credentials.h>
#include <grpc/grpc_security.h>
#include <grpc/support/port_platform.h>

namespace grpc_core {
/* Opaque types. */
// A struct that stores the credential data presented to the peer in handshake
// to show local identity. The private key and certificate chain must be PEM
// encoded and the public key in the leaf certificate must correspond to the
// given private key.
struct IdentityKeyCertPair {
  std::string private_key_pem;
  std::string certificate_chain_pem;
};

// TODO(gtcooke94) - Placeholder for SPIFFE Trust Map Support
class SpiffeTrustMap {};

/** Provides identity credentials and root certificates.
 */
// This represents a potential decoupling of roots and identity chains, with
// further extension points for something like SPIFFE bundles
class CertificateProviderInterface {
 public:
  virtual ~CertificateProviderInterface() = default;

  // Starts the provider. Must be called before the provider is used for any TLS
  // handshakes. Does important internal setup steps.
  void Start();

  // CredentialType represents the different types of credentials that the
  // provider can provide.
  enum CredentialType {
    // The case of a SPIFFE trust bundle still falls into RootCertificates, it's
    // just another way of representing root information
    RootCertificates,
    IdentityChainAndPrivateKey
  };

 protected:
  // Provider implementations MUST provide a OnWatchStarted callback that
  // will
  // be called by the internal stack. This will be invoked when a new
  // certificate name is starting to be used internally. When being invoked
  // for
  // a new certificate, this callback should call SetRootCertificates or
  // SetIdentityChainAndPrivateKey to do the initial population the
  // certificate
  // data in the internal stack.
  // cert_name The name of the certificates being watched.
  // type The type of certificates being watched.
  virtual void OnWatchStarted(std::string name, CredentialType type) = 0;

  // Provider implementations MUST provide a OnWatchStarted callback that will
  // be called by the internal stack. This will be invoked when a certificate
  // name is no longer being used internally.
  // cert_name The name of the certificates being watched.
  // type The type of certificates being watched.
  virtual void OnWatchStopped(std::string name, CredentialType type) = 0;

  // Sets the root certificates based on their name.
  // This value is layered and represents the following.
  // The top level `absl::StatusOr` represents setting an error or a value. If
  // the input is a status, it will be propagated across the internal stack as
  // an error.
  // The next layer is an `absl::optional`. This allows the user to set a value
  // or `absl::nullopt`, with `absl::nullopt` representing a deletion/un-setting
  // of the root certificate data.
  // The last layer is an `absl::variant`. This is an extension point for us to
  // add other kinds of root information, for example SPIFFE trust bundles.
  void SetRootCertificates(
      absl::string_view name,
      absl::StatusOr<absl::optional<absl::variant<std::string, SpiffeTrustMap>>>
          root_data);

  // Sets the identity chain and private key based on their name.
  // This value is layered and represents the following.
  // The top level `absl::StatusOr` represents setting an error or a value. If
  // the input is a status, it will be propagated across the internal stack as
  // an error.
  // The next layer is an `absl::optional`. This allows the user to set a value
  // or `absl::nullopt`, with `absl::nullopt` representing a deletion/un-setting
  // of the identity chain and private key data.
  void SetIdentityChainAndPrivateKey(
      absl::string_view name,
      absl::StatusOr<absl::optional<absl::Span<IdentityKeyCertPair>>>
          pem_key_cert_pairs);

 private:
  class TlsCertificateDistributor;
  std::unique_ptr<TlsCertificateDistributor> distributor_;
};
}  // namespace grpc_core

#endif  // GRPC_GRPC_CERTIFICATE_PROVIDER_H