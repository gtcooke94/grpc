//
//
// Copyright 2023 gRPC authors.
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
#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "absl/synchronization/notification.h"

#include <grpc/grpc_security.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>

#include "src/core/lib/iomgr/load_file.h"
#include "src/cpp/client/secure_credentials.h"
#include "test/core/util/port.h"
#include "test/core/util/test_config.h"
#include "test/core/util/tls_utils.h"
#include "test/cpp/end2end/test_service_impl.h"

namespace grpc {
namespace testing {
namespace {

const char* kSslTsiTestCrlSupportedCredentialsDir =
    "test/core/tsi/test_creds/crl_data/";
const char* kSslTsiTestCrlSupportedCrlDir =
    "test/core/tsi/test_creds/crl_data/crls/";
const char* kSslTsiTestCrlSupportedCrlDirMissingIntermediate =
    "test/core/tsi/test_creds/crl_data/crls_missing_intermediate/";
const char* kSslTsiTestCrlSupportedCrlDirMissingRoot =
    "test/core/tsi/test_creds/crl_data/crls_missing_root/";
const char* kSslTsiTestFaultyCrlsDir = "bad_path/";
const char* kRootPath = "test/core/tsi/test_creds/crl_data/ca.pem";
const char* kRevokedKeyPath = "test/core/tsi/test_creds/crl_data/revoked.key";
const char* kRevokedCertPath = "test/core/tsi/test_creds/crl_data/revoked.pem";
const char* kValidKeyPath = "test/core/tsi/test_creds/crl_data/valid.key";
const char* kValidCertPath = "test/core/tsi/test_creds/crl_data/valid.pem";

const char* kRevokedIntermediateKeyPath =
    "test/core/tsi/test_creds/crl_data/leaf_signed_by_intermediate.key";
const char* kRevokedIntermediateCertPath =
    "test/core/tsi/test_creds/crl_data/leaf_and_intermediate_chain.pem";
const char* kRootCrlPath = "test/core/tsi/test_creds/crl_data/crls/current.crl";
const char* kIntermediateCrlPath =
    "test/core/tsi/test_creds/crl_data/crls/intermediate.crl";

constexpr char kMessage[] = "Hello";

class CrlProviderTest : public ::testing::Test {
 protected:
  void RunServer(absl::Notification* notification, absl::string_view server_key,
                 absl::string_view server_cert) {
    experimental::IdentityKeyCertPair key_cert_pair;
    // std::string server_key =
    // grpc_core::testing::GetFileContents(kValidKeyPath); std::string
    // server_cert =
    //     grpc_core::testing::GetFileContents(kValidCertPath);
    std::string root = grpc_core::testing::GetFileContents(kRootPath);
    key_cert_pair.private_key = server_key.data();
    key_cert_pair.certificate_chain = server_cert.data();
    std::vector<experimental::IdentityKeyCertPair> identity_key_cert_pairs;
    identity_key_cert_pairs.emplace_back(key_cert_pair);
    auto certificate_provider =
        std::make_shared<experimental::StaticDataCertificateProvider>(
            root, identity_key_cert_pairs);
    grpc::experimental::TlsServerCredentialsOptions options(
        certificate_provider);
    options.watch_root_certs();
    options.set_root_cert_name("root");
    options.watch_identity_key_cert_pairs();
    options.set_identity_cert_name("identity");
    options.set_cert_request_type(
        GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
    auto server_credentials = grpc::experimental::TlsServerCredentials(options);
    GPR_ASSERT(server_credentials.get() != nullptr);

    grpc::ServerBuilder builder;
    TestServiceImpl service_;

    builder.AddListeningPort(server_addr_, server_credentials);
    builder.RegisterService("foo.test.google.fr", &service_);
    server_ = builder.BuildAndStart();
    notification->Notify();
    server_->Wait();
  }

  void TearDown() override {
    if (server_ != nullptr) {
      server_->Shutdown();
      server_thread_->join();
      delete server_thread_;
    }
  }

  TestServiceImpl service_;
  std::unique_ptr<Server> server_ = nullptr;
  std::thread* server_thread_ = nullptr;
  std::string server_addr_;
};

void DoRpc(const std::string& server_addr,
           const experimental::TlsChannelCredentialsOptions& tls_options,
           bool expect_success) {
  ChannelArguments channel_args;
  channel_args.SetSslTargetNameOverride("foo.test.google.fr");
  std::shared_ptr<Channel> channel = grpc::CreateCustomChannel(
      server_addr, grpc::experimental::TlsCredentials(tls_options),
      channel_args);

  auto stub = grpc::testing::EchoTestService::NewStub(channel);
  grpc::testing::EchoRequest request;
  grpc::testing::EchoResponse response;
  request.set_message(kMessage);
  ClientContext context;
  context.set_deadline(grpc_timeout_seconds_to_deadline(/*time_s=*/10));
  grpc::Status result = stub->Echo(&context, request, &response);
  if (expect_success) {
    EXPECT_TRUE(result.ok());
    if (!result.ok()) {
      gpr_log(GPR_ERROR, "%s, %s", result.error_message().c_str(),
              result.error_details().c_str());
    }
    EXPECT_EQ(response.message(), kMessage);
  } else {
    EXPECT_FALSE(result.ok());
  }
}

TEST_F(CrlProviderTest, CrlProviderValid) {
  server_addr_ = absl::StrCat("localhost:",
                              std::to_string(grpc_pick_unused_port_or_die()));
  absl::Notification notification;
  std::string server_key = grpc_core::testing::GetFileContents(kValidKeyPath);
  std::string server_cert = grpc_core::testing::GetFileContents(kValidCertPath);
  server_thread_ = new std::thread(
      [&]() { RunServer(&notification, server_key, server_cert); });
  notification.WaitForNotification();

  std::string root_cert = grpc_core::testing::GetFileContents(kRootPath);
  std::string client_key = grpc_core::testing::GetFileContents(kValidKeyPath);
  std::string client_cert = grpc_core::testing::GetFileContents(kValidCertPath);
  experimental::IdentityKeyCertPair key_cert_pair;
  key_cert_pair.private_key = client_key;
  key_cert_pair.certificate_chain = client_cert;
  std::vector<experimental::IdentityKeyCertPair> identity_key_cert_pairs;
  identity_key_cert_pairs.emplace_back(key_cert_pair);
  auto certificate_provider =
      std::make_shared<experimental::StaticDataCertificateProvider>(
          root_cert, identity_key_cert_pairs);
  grpc::experimental::TlsChannelCredentialsOptions options;
  options.set_certificate_provider(certificate_provider);
  options.watch_root_certs();
  options.set_root_cert_name("root");
  options.watch_identity_key_cert_pairs();
  options.set_identity_cert_name("identity");
  std::string root_crl = grpc_core::testing::GetFileContents(kRootCrlPath);
  std::vector<std::string> crls = {root_crl};

  absl::StatusOr<std::shared_ptr<grpc_core::experimental::CrlProvider>> result =
      grpc_core::experimental::StaticCrlProvider::Create(crls);
  ASSERT_TRUE(result.ok());
  std::shared_ptr<grpc_core::experimental::CrlProvider> provider =
      std::move(*result);

  options.set_crl_provider(provider);
  options.set_check_call_host(false);
  auto verifier = std::make_shared<experimental::NoOpCertificateVerifier>();
  options.set_certificate_verifier(verifier);

  DoRpc(server_addr_, options, true);
}

TEST_F(CrlProviderTest, CrlProviderRevokedServer) {
  server_addr_ = absl::StrCat("localhost:",
                              std::to_string(grpc_pick_unused_port_or_die()));
  absl::Notification notification;
  std::string server_key = grpc_core::testing::GetFileContents(kRevokedKeyPath);
  std::string server_cert =
      grpc_core::testing::GetFileContents(kRevokedCertPath);
  server_thread_ = new std::thread(
      [&]() { RunServer(&notification, server_key, server_cert); });
  notification.WaitForNotification();

  std::string root_cert = grpc_core::testing::GetFileContents(kRootPath);
  std::string client_key = grpc_core::testing::GetFileContents(kValidKeyPath);
  std::string client_cert = grpc_core::testing::GetFileContents(kValidCertPath);
  experimental::IdentityKeyCertPair key_cert_pair;
  key_cert_pair.private_key = client_key;
  key_cert_pair.certificate_chain = client_cert;
  std::vector<experimental::IdentityKeyCertPair> identity_key_cert_pairs;
  identity_key_cert_pairs.emplace_back(key_cert_pair);
  auto certificate_provider =
      std::make_shared<experimental::StaticDataCertificateProvider>(
          root_cert, identity_key_cert_pairs);
  grpc::experimental::TlsChannelCredentialsOptions options;
  options.set_certificate_provider(certificate_provider);
  options.watch_root_certs();
  options.set_root_cert_name("root");
  options.watch_identity_key_cert_pairs();
  options.set_identity_cert_name("identity");
  std::string root_crl = grpc_core::testing::GetFileContents(kRootCrlPath);
  std::vector<std::string> crls = {root_crl};

  absl::StatusOr<std::shared_ptr<grpc_core::experimental::CrlProvider>> result =
      grpc_core::experimental::StaticCrlProvider::Create(crls);
  ASSERT_TRUE(result.ok());
  std::shared_ptr<grpc_core::experimental::CrlProvider> provider =
      std::move(*result);

  options.set_crl_provider(provider);
  options.set_check_call_host(false);
  auto verifier = std::make_shared<experimental::NoOpCertificateVerifier>();
  options.set_certificate_verifier(verifier);

  DoRpc(server_addr_, options, false);
}

}  // namespace
}  // namespace testing
}  // namespace grpc

int main(int argc, char** argv) {
  grpc::testing::TestEnvironment env(&argc, argv);
  ::testing::InitGoogleTest(&argc, argv);
  int ret = RUN_ALL_TESTS();
  return ret;
}
