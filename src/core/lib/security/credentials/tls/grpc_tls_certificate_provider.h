//
// Copyright 2020 gRPC authors.
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

#ifndef GRPC_SRC_CORE_LIB_SECURITY_CREDENTIALS_TLS_GRPC_TLS_CERTIFICATE_PROVIDER_H
#define GRPC_SRC_CORE_LIB_SECURITY_CREDENTIALS_TLS_GRPC_TLS_CERTIFICATE_PROVIDER_H

#include <stdint.h>

#include <map>
#include <string>

#include "absl/base/thread_annotations.h"
#include "absl/log/check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

#include <grpc/grpc_certificate_provider.h>
#include <grpc/grpc_security.h>
#include <grpc/support/log.h>
#include <grpc/support/port_platform.h>
#include <grpc/support/sync.h>

#include "src/core/lib/gprpp/ref_counted.h"
#include "src/core/lib/gprpp/ref_counted_ptr.h"
#include "src/core/lib/gprpp/sync.h"
#include "src/core/lib/gprpp/thd.h"
#include "src/core/lib/gprpp/unique_type_name.h"
#include "src/core/lib/security/credentials/tls/grpc_tls_certificate_distributor.h"
#include "src/core/lib/security/security_connector/ssl_utils.h"
#include "src/core/util/useful.h"

// Interface for a grpc_tls_certificate_provider that handles the process to
// fetch credentials and validation contexts. Implementations are free to rely
// on local or remote sources to fetch the latest secrets, and free to share any
// state among different instances as they deem fit.
//
// On creation, grpc_tls_certificate_provider creates a
// TlsCertificateDistributor object. When the credentials and validation
// contexts become valid or changed, a grpc_tls_certificate_provider should
// notify its distributor so as to propagate the update to the watchers.
struct grpc_tls_certificate_provider
    : public grpc_core::RefCounted<grpc_tls_certificate_provider> {
 public:
  virtual std::shared_ptr<TlsCertificateDistributorImpl> distributor()
      const = 0;

  // Compares this grpc_tls_certificate_provider object with \a other.
  // If this method returns 0, it means that gRPC can treat the two certificate
  // providers as effectively the same. This method is used to compare
  // `grpc_tls_certificate_provider` objects when they are present in
  // channel_args. One important usage of this is when channel args are used in
  // SubchannelKey, which leads to a useful property that allows subchannels to
  // be reused when two different `grpc_tls_certificate_provider` objects are
  // used but they compare as equal (assuming other channel args match).
  int Compare(const grpc_tls_certificate_provider* other) const {
    CHECK_NE(other, nullptr);
    int r = type().Compare(other->type());
    if (r != 0) return r;
    return CompareImpl(other);
  }

  // The pointer value \a type is used to uniquely identify a creds
  // implementation for down-casting purposes. Every provider implementation
  // should use a unique string instance, which should be returned by all
  // instances of that provider implementation.
  virtual grpc_core::UniqueTypeName type() const = 0;

  static absl::string_view ChannelArgName();
  static int ChannelArgsCompare(const grpc_tls_certificate_provider* a,
                                const grpc_tls_certificate_provider* b) {
    return a->Compare(b);
  }

 private:
  // Implementation for `Compare` method intended to be overridden by
  // subclasses. Only invoked if `type()` and `other->type()` point to the same
  // string.
  virtual int CompareImpl(const grpc_tls_certificate_provider* other) const = 0;
};

namespace grpc_core {
namespace compat {

// A basic provider class that will get credentials from string during
// initialization.
class StaticDataCertificateProvider final
    : public grpc_tls_certificate_provider {
 public:
  StaticDataCertificateProvider(std::string root_certificate,
                                PemKeyCertPairList pem_key_cert_pairs);

  ~StaticDataCertificateProvider() override;

  std::shared_ptr<TlsCertificateDistributorImpl> distributor() const override {
    return distributor_;
  }

  UniqueTypeName type() const override;

 private:
  struct WatcherInfo {
    bool root_being_watched = false;
    bool identity_being_watched = false;
  };

  int CompareImpl(const grpc_tls_certificate_provider* other) const override {
    // TODO(yashykt): Maybe do something better here.
    return QsortCompare(static_cast<const grpc_tls_certificate_provider*>(this),
                        other);
  }

  std::shared_ptr<TlsCertificateDistributorImpl> distributor_;
  std::string root_certificate_;
  PemKeyCertPairList pem_key_cert_pairs_;
  // Guards members below.
  Mutex mu_;
  // Stores each cert_name we get from the distributor callback and its watcher
  // information.
  std::map<std::string, WatcherInfo> watcher_info_;
};

// A provider class that will watch the credential changes on the file system.
class FileWatcherCertificateProvider final
    : public grpc_tls_certificate_provider {
 public:
  FileWatcherCertificateProvider(std::string private_key_path,
                                 std::string identity_certificate_path,
                                 std::string root_cert_path,
                                 int64_t refresh_interval_sec);

  ~FileWatcherCertificateProvider() override;

  std::shared_ptr<TlsCertificateDistributorImpl> distributor() const override {
    return distributor_;
  }

  UniqueTypeName type() const override;

  int64_t TestOnlyGetRefreshIntervalSecond() const;

 private:
  struct WatcherInfo {
    bool root_being_watched = false;
    bool identity_being_watched = false;
  };

  int CompareImpl(const grpc_tls_certificate_provider* other) const override {
    // TODO(yashykt): Maybe do something better here.
    return QsortCompare(static_cast<const grpc_tls_certificate_provider*>(this),
                        other);
  }

  // Force an update from the file system regardless of the interval.
  void ForceUpdate();
  // Read the root certificates from files and update the distributor.
  absl::optional<std::string> ReadRootCertificatesFromFile(
      const std::string& root_cert_full_path);
  // Read the private key and the certificate chain from files and update the
  // distributor.
  absl::optional<PemKeyCertPairList> ReadIdentityKeyCertPairFromFiles(
      const std::string& private_key_path,
      const std::string& identity_certificate_path);

  // Information that is used by the refreshing thread.
  std::string private_key_path_;
  std::string identity_certificate_path_;
  std::string root_cert_path_;
  int64_t refresh_interval_sec_ = 0;

  std::shared_ptr<TlsCertificateDistributorImpl> distributor_;
  Thread refresh_thread_;
  gpr_event shutdown_event_;

  // Guards members below.
  Mutex mu_;
  // The most-recent credential data. It will be empty if the most recent read
  // attempt failed.
  std::string root_certificate_ ABSL_GUARDED_BY(mu_);
  PemKeyCertPairList pem_key_cert_pairs_ ABSL_GUARDED_BY(mu_);
  // Stores each cert_name we get from the distributor callback and its watcher
  // information.
  std::map<std::string, WatcherInfo> watcher_info_ ABSL_GUARDED_BY(mu_);
};

}  // namespace compat

//  Checks if the private key matches the certificate's public key.
//  Returns a not-OK status on failure, or a bool indicating
//  whether the key/cert pair matches.
absl::StatusOr<bool> PrivateKeyAndCertificateMatch(
    absl::string_view private_key, absl::string_view cert_chain);

// A basic CertificateProviderInterface implementation that will load
// credential data from static string during initialization. This provider
// will always return the same certificate data for all cert names, and
// reloading is not supported.
class StaticDataCertificateProvider
    : public grpc_core::CertificateProviderInterface {
 public:
  StaticDataCertificateProvider(
      absl::string_view root_certificate,
      const absl::Span<PemKeyCertPair>& identity_key_cert_pairs);

  explicit StaticDataCertificateProvider(absl::string_view root_certificate);

  explicit StaticDataCertificateProvider(
      const absl::Span<PemKeyCertPair>& identity_key_cert_pairs);

  void OnWatchStarted(absl::string_view name, CredentialType type) override;
  void OnWatchStopped(absl::string_view name, CredentialType type) override;

 private:
  struct WatcherInfo {
    bool root_being_watched = false;
    bool identity_being_watched = false;
  };
  std::string root_certificate_;
  absl::Span<PemKeyCertPair> pem_key_cert_pairs_;
  // Guards members below.
  Mutex mu_;
  // Stores each cert_name we get from the distributor callback and its
  // watcher information.
  std::map<std::string, WatcherInfo> watcher_info_;
};

// A CertificateProviderInterface implementation that will watch the
// credential changes on the file system. This provider will always return the
// up-to-date certificate data for all the cert names callers set through
// |TlsCredentialsBuilder|. Several things to note:
// 1. This API only supports one key-certificate file and hence one set of
// identity key-certificate pair, so SNI(Server Name Indication) is not
// supported.
// 2. The private key and identity certificate should always match. This API
// guarantees atomic read, and it is the callers' responsibility to do atomic
// updates. There are many ways to atomically update the key and certificates
// in the file system. To name a few:
//   1)  creating a new directory, renaming the old directory to a new name,
//   and then renaming the new directory to the original name of the old
//   directory. 2)  using a symlink for the directory. When need to change,
//   put new credential data in a new directory, and change symlink.
class FileWatcherCertificateProvider final
    : public grpc_core::CertificateProviderInterface {
 public:
  // Constructor to get credential updates from root and identity file paths.
  //
  // @param private_key_path is the file path of the private key.
  // @param identity_certificate_path is the file path of the identity
  // certificate chain.
  // @param root_cert_path is the file path to the root certificate bundle.
  // @param refresh_interval_sec is the refreshing interval that we will check
  // the files for updates.
  FileWatcherCertificateProvider(absl::string_view private_key_path,
                                 absl::string_view identity_certificate_path,
                                 absl::string_view root_cert_path,
                                 unsigned int refresh_interval_sec);

  // Constructor to get credential updates from identity file paths only.
  FileWatcherCertificateProvider(absl::string_view private_key_path,
                                 absl::string_view identity_certificate_path,
                                 unsigned int refresh_interval_sec);

  // Constructor to get credential updates from root file path only.
  FileWatcherCertificateProvider(absl::string_view root_cert_path,
                                 unsigned int refresh_interval_sec);

  ~FileWatcherCertificateProvider() override;

 protected:
  void OnWatchStarted(absl::string_view name, CredentialType type) override;
  void OnWatchStopped(absl::string_view name, CredentialType type) override;
};
}  // namespace grpc_core

#endif  // GRPC_SRC_CORE_LIB_SECURITY_CREDENTIALS_TLS_GRPC_TLS_CERTIFICATE_PROVIDER_H
