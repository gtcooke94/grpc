// Copyright 2025 gRPC authors.
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

#include <grpc/grpc.h>
#include <grpc/support/alloc.h>
#include <grpc/support/string_util.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <memory>
#include <utility>

#include "absl/log/check.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "src/core/credentials/transport/security_connector.h"
#include "src/core/tsi/ssl_transport_security.h"
#include "src/core/tsi/transport_security.h"
#include "src/core/tsi/transport_security_interface.h"
#include "src/core/util/crash.h"
#include "test/core/test_util/test_config.h"
#include "test/core/test_util/tls_utils.h"
#include "test/core/tsi/transport_security_test_lib.h"

extern "C" {
#include <openssl/crypto.h>
#include <openssl/pem.h>
}

namespace {
constexpr absl::string_view kCaPemPath =
    "test/core/tsi/test_creds/spiffe_end2end/ca.pem";
constexpr absl::string_view kClientKeyPath =
    "test/core/tsi/test_creds/spiffe_end2end/client.key";
constexpr absl::string_view kClientCertPath =
    "test/core/tsi/test_creds/spiffe_end2end/client_spiffe.pem";
constexpr absl::string_view kServerKeyPath =
    "test/core/tsi/test_creds/spiffe_end2end/server.key";
constexpr absl::string_view kServerCertPath =
    "test/core/tsi/test_creds/spiffe_end2end/server_spiffe.pem";
constexpr absl::string_view kServerChainKeyPath =
    "test/core/tsi/test_creds/spiffe_end2end/leaf_signed_by_intermediate.key";
constexpr absl::string_view kServerChainCertPath =
    "test/core/tsi/test_creds/spiffe_end2end/leaf_and_intermediate_chain.pem";
constexpr absl::string_view kClientSpiffeBundleMapPath =
    "test/core/tsi/test_creds/spiffe_end2end/client_spiffebundle.json";
constexpr absl::string_view kServerSpiffeBundleMapPath =
    "test/core/tsi/test_creds/spiffe_end2end/server_spiffebundle.json";

constexpr absl::string_view kNonSpiffeKeyPath =
    "test/core/tsi/test_creds/crl_data/valid.key";
constexpr absl::string_view kNonSpiffeCertPath =
    "test/core/tsi/test_creds/crl_data/valid.pem";
constexpr absl::string_view kNonSpiffeCAPath =
    "test/core/tsi/test_creds/crl_data/ca.pem";

std::shared_ptr<grpc_core::SpiffeBundleMap> GetClientSpiffeBundleMap() {
  auto map = grpc_core::SpiffeBundleMap::FromFile(kClientSpiffeBundleMapPath);
  EXPECT_TRUE(map.ok()) << map.status();
  return std::make_shared<grpc_core::SpiffeBundleMap>(*map);
}

std::shared_ptr<grpc_core::SpiffeBundleMap> GetServerSpiffeBundleMap() {
  auto map = grpc_core::SpiffeBundleMap::FromFile(kServerSpiffeBundleMapPath);
  EXPECT_TRUE(map.ok()) << map.status();
  return std::make_shared<grpc_core::SpiffeBundleMap>(*map);
}

class SpiffeSslTransportSecurityTest
    : public testing::TestWithParam<tsi_tls_version> {
 protected:
  // A tsi_test_fixture implementation.
  class SslTsiTestFixture {
   public:
    SslTsiTestFixture(
        absl::string_view server_key_path, absl::string_view server_cert_path,
        absl::string_view client_key_path, absl::string_view client_cert_path,
        std::shared_ptr<grpc_core::SpiffeBundleMap> server_spiffe_bundle_map,
        std::shared_ptr<grpc_core::SpiffeBundleMap> client_spiffe_bundle_map,
        absl::string_view ca_path, bool expect_server_success,
        bool expect_client_success_1_2, bool expect_client_success_1_3) {
      tsi_test_fixture_init(&base_);
      base_.test_unused_bytes = true;
      base_.vtable = &kVtable;
      server_key_ = grpc_core::testing::GetFileContents(server_key_path.data());
      server_cert_ =
          grpc_core::testing::GetFileContents(server_cert_path.data());
      client_key_ = grpc_core::testing::GetFileContents(client_key_path.data());
      client_cert_ =
          grpc_core::testing::GetFileContents(client_cert_path.data());
      // We set this and it shouldn't matter if we set spiffe bundles
      root_cert_ = grpc_core::testing::GetFileContents(ca_path.data());
      server_spiffe_bundle_map_ = server_spiffe_bundle_map;
      client_spiffe_bundle_map_ = client_spiffe_bundle_map;
      expect_server_success_ = expect_server_success;
      expect_client_success_1_2_ = expect_client_success_1_2;
      expect_client_success_1_3_ = expect_client_success_1_3;

      server_pem_key_cert_pairs_ = static_cast<tsi_ssl_pem_key_cert_pair*>(
          gpr_malloc(sizeof(tsi_ssl_pem_key_cert_pair)));
      server_pem_key_cert_pairs_[0].private_key = server_key_.c_str();
      server_pem_key_cert_pairs_[0].cert_chain = server_cert_.c_str();
      client_pem_key_cert_pairs_ = static_cast<tsi_ssl_pem_key_cert_pair*>(
          gpr_malloc(sizeof(tsi_ssl_pem_key_cert_pair)));
      client_pem_key_cert_pairs_[0].private_key = client_key_.c_str();
      client_pem_key_cert_pairs_[0].cert_chain = client_cert_.c_str();
      // CHECK_NE(root_store_, nullptr);
    }

    void Run() {
      tsi_test_do_handshake(&base_);
      tsi_test_fixture_destroy(&base_);
    }

    ~SslTsiTestFixture() {
      gpr_free(server_pem_key_cert_pairs_);
      gpr_free(client_pem_key_cert_pairs_);

      tsi_ssl_root_certs_store_destroy(root_store_);
      tsi_ssl_server_handshaker_factory_unref(server_handshaker_factory_);
      tsi_ssl_client_handshaker_factory_unref(client_handshaker_factory_);
    }

   private:
    static void SetupHandshakers(tsi_test_fixture* fixture) {
      CHECK_NE(fixture, nullptr);
      auto* self = reinterpret_cast<SslTsiTestFixture*>(fixture);
      self->SetupHandshakers();
    }

    void SetupHandshakers() {
      // Create client handshaker factory.
      tsi_ssl_client_handshaker_options client_options;
      client_options.pem_key_cert_pair = client_pem_key_cert_pairs_;
      client_options.pem_root_certs = root_cert_.c_str();
      client_options.root_store = root_store_;
      client_options.spiffe_bundle_map = client_spiffe_bundle_map_;
      client_options.min_tls_version = GetParam();
      client_options.max_tls_version = GetParam();
      EXPECT_EQ(tsi_create_ssl_client_handshaker_factory_with_options(
                    &client_options, &client_handshaker_factory_),
                TSI_OK);
      // Create server handshaker factory.
      tsi_ssl_server_handshaker_options server_options;
      server_options.pem_key_cert_pairs = server_pem_key_cert_pairs_;
      server_options.num_key_cert_pairs = 1;
      server_options.pem_client_root_certs = root_cert_.c_str();
      server_options.spiffe_bundle_map = server_spiffe_bundle_map_;
      server_options.client_certificate_request =
          TSI_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
      server_options.session_ticket_key = nullptr;
      server_options.session_ticket_key_size = 0;
      server_options.min_tls_version = GetParam();
      server_options.max_tls_version = GetParam();
      EXPECT_EQ(tsi_create_ssl_server_handshaker_factory_with_options(
                    &server_options, &server_handshaker_factory_),
                TSI_OK);
      // Create server and client handshakers.
      EXPECT_EQ(tsi_ssl_client_handshaker_factory_create_handshaker(
                    client_handshaker_factory_, nullptr, 0, 0,
                    /*alpn_preferred_protocol_list=*/std::nullopt,
                    &base_.client_handshaker),
                TSI_OK);
      EXPECT_EQ(tsi_ssl_server_handshaker_factory_create_handshaker(
                    server_handshaker_factory_, 0, 0, &base_.server_handshaker),
                TSI_OK);
    }

    static void CheckHandshakerPeers(tsi_test_fixture* fixture) {
      CHECK_NE(fixture, nullptr);
      auto* self = reinterpret_cast<SslTsiTestFixture*>(fixture);
      self->CheckHandshakerPeers();
    }

    void CheckHandshakerPeers() {
      // In TLS 1.3, the client-side handshake succeeds even if the client
      // sends a revoked certificate. In such a case, the server would fail
      // the TLS handshake and send an alert to the client as the first
      // application data message. In TLS 1.2, the client-side handshake will
      // fail if the client sends a revoked certificate.
      //
      // For OpenSSL versions < 1.1, TLS 1.3 is not supported, so the
      // client-side handshake should succeed precisely when the server-side
      // handshake succeeds.
      //
      // For the intermediate cases, we have a CA -> Intermediate CA -> Leaf
      // Cert chain in which the Intermediate CA cert is revoked by the CA. We
      // test 3 cases. Note: A CRL not existing should not make the handshake
      // fail
      // 1. CRL Directory with CA's CRL and Intermediate CA's CRL -> Handshake
      // fails due to revoked cert
      // 2. CRL Directory with CA's CRL but missing Intermediate CA's CRL ->
      // Handshake fails due to revoked cert
      // 3. CRL Directory without CA's CRL with but Intermediate CA's CRL ->
      // Handshake succeeds because the CRL that revokes the cert is not
      // present.
      bool expect_server_success = expect_server_success_;
      bool expect_client_success = false;
#if OPENSSL_VERSION_NUMBER >= 0x10100000
      expect_client_success = GetParam() == tsi_tls_version::TSI_TLS1_2
                                  ? expect_client_success_1_2_
                                  : expect_client_success_1_3_;
#else
      //  If using OpenSSL version < 1.1, the CRL revocation won't
      //  be enabled anyways, so we always expect the connection to
      //  be successful.
      expect_server_success = true;
      expect_client_success = expect_server_success;
#endif
      tsi_peer peer;
      if (expect_client_success) {
        EXPECT_EQ(
            tsi_handshaker_result_extract_peer(base_.client_result, &peer),
            TSI_OK);
        tsi_peer_destruct(&peer);
      } else {
        EXPECT_EQ(base_.client_result, nullptr);
      }
      if (expect_server_success) {
        EXPECT_EQ(
            tsi_handshaker_result_extract_peer(base_.server_result, &peer),
            TSI_OK);
        tsi_peer_destruct(&peer);
      } else {
        EXPECT_EQ(base_.server_result, nullptr);
      }
    }

    static void Destruct(tsi_test_fixture* fixture) {
      auto* self = reinterpret_cast<SslTsiTestFixture*>(fixture);
      delete self;
    }

    static struct tsi_test_fixture_vtable kVtable;

    tsi_test_fixture base_;
    std::string root_cert_;
    tsi_ssl_root_certs_store* root_store_;
    tsi_ssl_server_handshaker_factory* server_handshaker_factory_;
    tsi_ssl_client_handshaker_factory* client_handshaker_factory_;
    std::shared_ptr<grpc_core::SpiffeBundleMap> server_spiffe_bundle_map_;
    std::shared_ptr<grpc_core::SpiffeBundleMap> client_spiffe_bundle_map_;

    std::string server_key_;
    std::string server_cert_;
    std::string client_key_;
    std::string client_cert_;
    bool expect_server_success_;
    bool expect_client_success_1_2_;
    bool expect_client_success_1_3_;
    tsi_ssl_pem_key_cert_pair* client_pem_key_cert_pairs_;
    tsi_ssl_pem_key_cert_pair* server_pem_key_cert_pairs_;
  };
};

struct tsi_test_fixture_vtable
    SpiffeSslTransportSecurityTest::SslTsiTestFixture::kVtable = {
        &SpiffeSslTransportSecurityTest::SslTsiTestFixture::SetupHandshakers,
        &SpiffeSslTransportSecurityTest::SslTsiTestFixture::CheckHandshakerPeers,
        &SpiffeSslTransportSecurityTest::SslTsiTestFixture::Destruct};

// Valid SPIFFE Bundles on both sides with the root configured for the
// appropriate trust domain
TEST_P(SpiffeSslTransportSecurityTest, MTLSSpiffe) {
  auto* fixture = new SslTsiTestFixture(
      kServerKeyPath, kServerCertPath, kClientKeyPath, kClientCertPath,
      GetServerSpiffeBundleMap(), GetClientSpiffeBundleMap(), kNonSpiffeCAPath,
      /*expect_server_success=*/true,
      /*expect_client_success_1_2=*/true, /*expected_client_success_1_3=*/true);
  fixture->Run();
}

// Valid SPIFFE Bundles on both sides with the root configured for the
// appropriate trust domain, and a certificate chain with an intermediate CA on
// the server side
TEST_P(SpiffeSslTransportSecurityTest, MTLSSpiffeChain) {
  auto* fixture = new SslTsiTestFixture(
      kServerChainKeyPath, kServerChainCertPath, kClientKeyPath,
      kClientCertPath, GetServerSpiffeBundleMap(), GetClientSpiffeBundleMap(),
      kNonSpiffeCAPath,
      /*expect_server_success=*/true,
      /*expect_client_success_1_2=*/true, /*expected_client_success_1_3=*/true);
  fixture->Run();
}

// Just Spiffe bundles on the client side - the server side has the root
// configured as a certificate
TEST_P(SpiffeSslTransportSecurityTest, ClientSideSpiffeBundle) {
  auto* fixture = new SslTsiTestFixture(
      kServerKeyPath, kServerCertPath, kClientKeyPath, kClientCertPath, nullptr,
      GetClientSpiffeBundleMap(), kCaPemPath,
      /*expect_server_success=*/true,
      /*expect_client_success_1_2=*/true, /*expected_client_success_1_3=*/true);
  fixture->Run();
}

// Just SPIFFE bundles on the server side - the client side has the root
// configured as a certificate
TEST_P(SpiffeSslTransportSecurityTest, ServerSideSpiffeBundle) {
  auto* fixture = new SslTsiTestFixture(
      kServerKeyPath, kServerCertPath, kClientKeyPath, kClientCertPath,
      GetServerSpiffeBundleMap(), nullptr, kCaPemPath,
      /*expect_server_success=*/true,
      /*expect_client_success_1_2=*/true, /*expected_client_success_1_3=*/true);
  fixture->Run();
}

// Use the good client spiffebundle on the server side so we don't get a
// matching trust domain on the server side for the client's leaf certificate
// Client-side TLS 1.3 sees success
TEST_P(SpiffeSslTransportSecurityTest, MTLSSpiffeServerMismatchFail) {
  auto* fixture = new SslTsiTestFixture(
      kServerKeyPath, kServerCertPath, kClientKeyPath, kClientCertPath,
      GetClientSpiffeBundleMap(), GetClientSpiffeBundleMap(), kNonSpiffeCAPath,
      /*expect_server_success=*/false,
      /*expect_client_success_1_2=*/false,
      /*expected_client_success_1_3=*/true);
  fixture->Run();
}

// Use the good server side spiffebundle on the client side so we don't get a
// matching trust domain on the client side for the server's leaf certificate
TEST_P(SpiffeSslTransportSecurityTest, MTLSSpiffeClientMismatchFail) {
  auto* fixture = new SslTsiTestFixture(
      kServerKeyPath, kServerCertPath, kClientKeyPath, kClientCertPath,
      GetServerSpiffeBundleMap(), GetServerSpiffeBundleMap(), kNonSpiffeCAPath,
      /*expect_server_success=*/false,
      /*expect_client_success_1_2=*/false,
      /*expected_client_success_1_3=*/false);
  fixture->Run();
}

TEST_P(SpiffeSslTransportSecurityTest, NonSpiffeServerCertFail) {
  auto* fixture = new SslTsiTestFixture(
      kNonSpiffeKeyPath, kNonSpiffeCertPath, kClientKeyPath, kClientCertPath,
      GetServerSpiffeBundleMap(), GetClientSpiffeBundleMap(), kNonSpiffeCAPath,
      /*expect_server_success=*/false,
      /*expect_client_success_1_2=*/false,
      /*expected_client_success_1_3=*/false);
  fixture->Run();
}

TEST_P(SpiffeSslTransportSecurityTest, NonSpiffeClientCertFail) {
  // TLS1.3 client will pass because it validates the server
  auto* fixture = new SslTsiTestFixture(
      kServerKeyPath, kServerCertPath, kNonSpiffeKeyPath, kNonSpiffeCertPath,
      GetServerSpiffeBundleMap(), GetClientSpiffeBundleMap(), kNonSpiffeCAPath,
      /*expect_server_success=*/false,
      /*expect_client_success_1_2=*/false,
      /*expected_client_success_1_3=*/true);
  fixture->Run();
}

// CRLs + Spiffe?

std::string TestNameSuffix(
    const ::testing::TestParamInfo<tsi_tls_version>& version) {
  if (version.param == tsi_tls_version::TSI_TLS1_2) return "TLS_1_2";
  CHECK(version.param == tsi_tls_version::TSI_TLS1_3);
  return "TLS_1_3";
}

INSTANTIATE_TEST_SUITE_P(TLSVersionsTest, SpiffeSslTransportSecurityTest,
                         testing::Values(tsi_tls_version::TSI_TLS1_2,
                                         tsi_tls_version::TSI_TLS1_3),
                         &TestNameSuffix);

}  // namespace

int main(int argc, char** argv) {
  grpc::testing::TestEnvironment env(&argc, argv);
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
