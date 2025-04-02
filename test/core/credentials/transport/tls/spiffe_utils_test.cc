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

#include <grpc/grpc.h>

#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/core/test_util/test_config.h"

using ::grpc_core::experimental::SpiffeId;

namespace grpc_core {
namespace testing {

using ::testing::TestWithParam;

struct SpiffeIdTestCase {
  std::string test_name;
  std::string spiffe_id;
  std::string status_contains;
};

using SpiffeIdTest = TestWithParam<SpiffeIdTestCase>;

TEST_P(SpiffeIdTest, SpiffeIdTestFailure) {
  const SpiffeIdTestCase& test_case = GetParam();
  absl::StatusOr<SpiffeId> spiffe_id =
      SpiffeId::FromString(test_case.spiffe_id);
  EXPECT_EQ(spiffe_id.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(spiffe_id.status().message(),
              ::testing::HasSubstr(test_case.status_contains));
}

INSTANTIATE_TEST_SUITE_P(
    SpifeIdTestFailureSuiteInstantiation,  // This name is only used for
                                           // instantiation
    SpiffeIdTest,  // This is the name of your parameterized test
    ::testing::ValuesIn<SpiffeIdTestCase>({
        {"Empty", "", "empty uri"},
        {"TooLong", std::string(2049, 'a'),
         "maximum allowed for SPIFFE ID is 2048"},
        {"ContainsHashtag", "ab#de", "cannot contain query fragments"},
        {"ContainsQuestionMark", "ab?de", "cannot contain query parameters"},
        {"DoesNotStartWithSpiffe", "www://foo/bar",
         "must start with spiffe://"},
        {"EndsWithSlash", "spiffe://foo/bar/", "cannot end with a /"},
        {"NoTrustDomain", "spiffe://", "cannot end with a /"},
        {"TrustDomainTooLong", absl::StrCat("spiffe://", std::string(256, 'a')),
         "Trust domain maximum length is 255 characters"},
        {"TrustDomainInvalidCharacter1", "spiffe://bad@domain",
         "contains invalid character @"},
        {"TrustDomainInvalidCharacter2", "spiffe://BadDomain",
         "contains invalid character B"},
        {"PathContainsRelativeModifier1", "spiffe://example/path/./foo",
         ". or .."},
        {"PathContainsRelativeModifier2", "spiffe://example/path/../foo",
         ". or .."},
        {"PathSegmentBadCharacter", "spiffe://example/path/foo.bar/@",
         "invalid character @"},
    }),
    [](const ::testing::TestParamInfo<SpiffeIdTest::ParamType>& info) {
      return info.param.test_name;
    });

}  // namespace testing
}  // namespace grpc_core

int main(int argc, char** argv) {
  grpc::testing::TestEnvironment env(&argc, argv);
  grpc_init();
  ::testing::InitGoogleTest(&argc, argv);
  int ret = RUN_ALL_TESTS();
  grpc_shutdown();
  return ret;
}
