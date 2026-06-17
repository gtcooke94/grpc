// Copyright 2026 gRPC authors.
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

#ifndef GRPC_SRC_CORE_HANDSHAKER_SECURITY_SECURITY_TELEMETRY_H
#define GRPC_SRC_CORE_HANDSHAKER_SECURITY_SECURITY_TELEMETRY_H

#include "src/core/telemetry/histogram.h"
#include "src/core/telemetry/instrument.h"

namespace grpc_core {

class ClientHandshakeTelemetryDomain final
    : public InstrumentDomain<ClientHandshakeTelemetryDomain> {
 public:
  using Backend = LowContentionBackend;
  static constexpr absl::string_view kName = "client_security_handshaker";
  GRPC_INSTRUMENT_DOMAIN_LABELS("grpc.security.handshaker.status",
                                "grpc.target",
                                "grpc.security.handshaker.resumed",
                                "grpc.lb.locality", "grpc.lb.backend_service");

  static inline const auto kHandshakes = RegisterCounter(
      "grpc.client.tls.handshakes",
      "Total number of client-side TLS handshakes", "{handshake}");
};

class ServerHandshakeTelemetryDomain final
    : public InstrumentDomain<ServerHandshakeTelemetryDomain> {
 public:
  using Backend = LowContentionBackend;
  static constexpr absl::string_view kName = "server_security_handshaker";
  GRPC_INSTRUMENT_DOMAIN_LABELS("grpc.security.handshaker.status",
                                "grpc.security.handshaker.resumed");

  static inline const auto kHandshakes = RegisterCounter(
      "grpc.server.tls.handshakes",
      "Total number of server-side TLS handshakes", "{handshake}");
};

class ClientTlsPrivateKeySigningTelemetryDomain final
    : public InstrumentDomain<ClientTlsPrivateKeySigningTelemetryDomain> {
 public:
  using Backend = LowContentionBackend;
  static constexpr absl::string_view kName = "client_tls_private_key_signing";
  GRPC_INSTRUMENT_DOMAIN_LABELS("grpc.status", "grpc.target",
                                "grpc.security.offload.provider",
                                "grpc.security.offload.algorithm",
                                "grpc.lb.locality", "grpc.lb.backend_service");

  static inline const auto kOffloadPrivateKeySigningDuration =
      RegisterHistogram<ExponentialHistogramShape>(
          "grpc.client.tls.offload_private_key_signing_duration",
          "EXPERIMENTAL: Measures the duration of the offloaded client "
          "private key signing operation.",
          "s", 100000000, 100);
};

class ServerTlsPrivateKeySigningTelemetryDomain final
    : public InstrumentDomain<ServerTlsPrivateKeySigningTelemetryDomain> {
 public:
  using Backend = LowContentionBackend;
  static constexpr absl::string_view kName = "server_tls_private_key_signing";
  GRPC_INSTRUMENT_DOMAIN_LABELS("grpc.status", "grpc.security.offload.provider",
                                "grpc.security.offload.algorithm");

  static inline const auto kOffloadPrivateKeySigningDuration =
      RegisterHistogram<ExponentialHistogramShape>(
          "grpc.server.tls.offload_private_key_signing_duration",
          "EXPERIMENTAL: Measures the duration of the offloaded private key "
          "signing operation.",
          "s", 100000000, 100);
};

}  // namespace grpc_core

#endif  // GRPC_SRC_CORE_HANDSHAKER_SECURITY_SECURITY_TELEMETRY_H
