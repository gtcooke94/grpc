//
//
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
//
//

#include "src/core/credentials/transport/tls/spiffe_utils.h"

#include "absl/strings/match.h"
#include "absl/strings/str_format.h"

namespace grpc_core {
namespace experimental {
namespace {

absl::Status doInitialUriValidation(absl::string_view uri) {
  if (uri.empty()) {
    return absl::InvalidArgumentError(
        "SpiffeId cannot be parse from empty uri");
  }
  if (uri.length() >= 2048) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "URI length is %d, maximum allowed for SPIFFE ID is 2048",
        uri.length()));
  }
  if (absl::StrContains(uri, "#")) {
    return absl::InvalidArgumentError(
        "SPIFFE ID cannot contain query fragments");
  }
  if (absl::StrContains(uri, "?")) {
    return absl::InvalidArgumentError(
        "SPIFFE ID cannot contain query parameters");
  }
  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<SpiffeId> SpiffeIdFromString(absl::string_view uri) {
  if (absl::Status status = doInitialUriValidation(uri); !status.ok()) {
    return status;
  }
}

}  // namespace experimental
}  // namespace grpc_core