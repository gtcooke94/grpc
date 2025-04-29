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

#ifndef GRPC_SRC_CORE_CREDENTIALS_TRANSPORT_TLS_SPIFFE_UTILS_H
#define GRPC_SRC_CORE_CREDENTIALS_TRANSPORT_TLS_SPIFFE_UTILS_H

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "src/core/util/json/json.h"
#include "src/core/util/json/json_object_loader.h"

namespace grpc_core {

// A representation of a SPIFFE ID per the spec:
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#the-spiffe-identity-and-verifiable-identity-document
class SpiffeId final {
 public:
  // Parses the input string as a SPIFFE ID, and returns an error status if the
  // input string is not a valid SPIFFE ID.
  static absl::StatusOr<SpiffeId> FromString(absl::string_view input);
  // Returns the trust domain of the SPIFFE ID
  absl::string_view trust_domain() { return trust_domain_; }
  // Returns the path of the SPIFFE ID
  absl::string_view path() { return path_; }

 private:
  SpiffeId(absl::string_view trust_domain, absl::string_view path)
      : trust_domain_(trust_domain), path_(path) {}
  const std::string trust_domain_;
  const std::string path_;
};

// An entry in the Key vector of a Spiffe Bundle Map
class SpiffeBundleKey {
 public:
  static const JsonLoaderInterface* JsonLoader(const JsonArgs&) {
    static const auto* loader = JsonObjectLoader<SpiffeBundleKey>()
                                    .Field("kty", &SpiffeBundleKey::kty)
                                    .OptionalField("kid", &SpiffeBundleKey::kid)
                                    .Field("use", &SpiffeBundleKey::use)
                                    .Field("x5c", &SpiffeBundleKey::x5c)
                                    .Field("n", &SpiffeBundleKey::n)
                                    .Field("e", &SpiffeBundleKey::e)
                                    .Finish();
    return loader;
  }

  void JsonPostLoad(const Json& json, const JsonArgs&,
                    ValidationErrors* errors);

 private:
  std::string kty;
  std::string kid;
  std::string use;
  std::vector<std::string> x5c;
  std::string n;
  std::string e;
};

// A Spiffe bundle
class SpiffeBundle {
 public:
  static const JsonLoaderInterface* JsonLoader(const JsonArgs&) {
    static const auto* loader =
        JsonObjectLoader<SpiffeBundle>()
            .Field("spiffe_sequence", &SpiffeBundle::spiffe_sequence)
            .Field("keys", &SpiffeBundle::keys)
            .Finish();
    return loader;
  }

 private:
  uint64_t spiffe_sequence;
  std::vector<SpiffeBundleKey> keys;
};

// A SpiffeBundleMap
class SpiffeBundleMap {
 public:
  static const JsonLoaderInterface* JsonLoader(const JsonArgs&) {
    static const auto* loader =
        JsonObjectLoader<SpiffeBundleMap>()
            .Field("trust_domains", &SpiffeBundleMap::bundles)
            .Finish();
    return loader;
  }

  void JsonPostLoad(const Json& json, const JsonArgs&,
                    ValidationErrors* errors);

  // Loads a SPIFFE Bundle Map from a json file representation. Returns a bad
  // status if there is a problem while loading the file and parsing the JSON. A
  // returned value represents a valid and SPIFFE Bundle Map.
  // The only supported use is configuring X509 roots for a given trust domain -
  // no other SPIFFE Bundle configurations are supported.
  static absl::StatusOr<SpiffeBundleMap> FromFile(absl::string_view file_path);

  absl::StatusOr<SpiffeBundle> Get(absl::string_view trust_domain);
  size_t size() { return bundles.size(); }

 private:
  struct StringCmp {
    using is_transparent = void;
    bool operator()(absl::string_view a, absl::string_view b) const {
      return a < b;
    }
  };

  std::map<std::string, SpiffeBundle, StringCmp> bundles;
};

}  // namespace grpc_core

#endif  // GRPC_SRC_CORE_CREDENTIALS_TRANSPORT_TLS_SPIFFE_UTILS_H