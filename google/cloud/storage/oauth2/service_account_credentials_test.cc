// Copyright 2018 Google LLC
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

#include "google/cloud/storage/oauth2/service_account_credentials.h"
#include "google/cloud/internal/setenv.h"
#include "google/cloud/storage/internal/nljson.h"
#include "google/cloud/storage/oauth2/credential_constants.h"
#include "google/cloud/storage/testing/mock_http_request.h"
#include <gmock/gmock.h>
#include <chrono>
#include <cstring>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace oauth2 {
namespace {
using storage::testing::MockHttpRequest;
using storage::testing::MockHttpRequestBuilder;
using ::testing::_;
using ::testing::An;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrEq;

// This "magic" assertion below was generated from helper script,
// "make_jwt_assertion_for_test_data.py". Note that when our JSON library dumps
// a string representation, the keys are always in alphabetical order; our
// helper script also takes special care to ensure Python dicts are dumped in
// this manner, as dumping the keys in a different order would result in a
// different Base64-encoded string, and thus a different assertion string.
constexpr char kExpectedAssertionParam[] =
    R"""(assertion=eyJhbGciOiJSUzI1NiIsImtpZCI6ImExYTExMWFhMTExMWExMWExMWExMWFhMTExYTExMWExYTExMTExMTEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL29hdXRoMi5nb29nbGVhcGlzLmNvbS90b2tlbiIsImV4cCI6MTUzMDA2MzkyNCwiaWF0IjoxNTMwMDYwMzI0LCJpc3MiOiJmb28tZW1haWxAZm9vLXByb2plY3QuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJzY29wZSI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2F1dGgvY2xvdWQtcGxhdGZvcm0ifQ.OtL40PSxdAB9rxRkXj-UeyuMhQCoT10WJY4ccOrPXriwm-DRl5AMgbBkQvVmWeYuPMTiFKWz_CMMBjVc3lFPW015eHvKT5r3ySGra1i8hJ9cDsWO7SdIGB-l00G-BdRxVEhN8U4C20eUhlvhtjXemOwlCFrKjF22rJB-ChiKy84rXs3O-Hz0dWmsSZPfVD9q-2S2vJdr9vz7NoP-fCmpxhQ3POVocYb-2OEM5c4Uo_e7lQTX3bRtVc19wz_wrTu9wMMMRYt52K8WPoWPURt7qpjHX88_EitXMzH-cJUQoDsgIoZ6vDlQMs7_nqNfgrlsGWHpPoSoGgvJMg1vJbzVLw)""";
constexpr long int kFixedJwtTimestamp = 1530060324;
constexpr char kGrantParamUnescaped[] =
    "urn:ietf:params:oauth:grant-type:jwt-bearer";
constexpr char kGrantParamEscaped[] =
    "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";
constexpr char kJsonKeyfileContents[] = R"""({
      "type": "service_account",
      "project_id": "foo-project",
      "private_key_id": "a1a111aa1111a11a11a11aa111a111a1a1111111",
      "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCltiF2oP3KJJ+S\ntTc1McylY+TuAi3AdohX7mmqIjd8a3eBYDHs7FlnUrFC4CRijCr0rUqYfg2pmk4a\n6TaKbQRAhWDJ7XD931g7EBvCtd8+JQBNWVKnP9ByJUaO0hWVniM50KTsWtyX3up/\nfS0W2R8Cyx4yvasE8QHH8gnNGtr94iiORDC7De2BwHi/iU8FxMVJAIyDLNfyk0hN\neheYKfIDBgJV2v6VaCOGWaZyEuD0FJ6wFeLybFBwibrLIBE5Y/StCrZoVZ5LocFP\nT4o8kT7bU6yonudSCyNMedYmqHj/iF8B2UN1WrYx8zvoDqZk0nxIglmEYKn/6U7U\ngyETGcW9AgMBAAECggEAC231vmkpwA7JG9UYbviVmSW79UecsLzsOAZnbtbn1VLT\nPg7sup7tprD/LXHoyIxK7S/jqINvPU65iuUhgCg3Rhz8+UiBhd0pCH/arlIdiPuD\n2xHpX8RIxAq6pGCsoPJ0kwkHSw8UTnxPV8ZCPSRyHV71oQHQgSl/WjNhRi6PQroB\nSqc/pS1m09cTwyKQIopBBVayRzmI2BtBxyhQp9I8t5b7PYkEZDQlbdq0j5Xipoov\n9EW0+Zvkh1FGNig8IJ9Wp+SZi3rd7KLpkyKPY7BK/g0nXBkDxn019cET0SdJOHQG\nDiHiv4yTRsDCHZhtEbAMKZEpku4WxtQ+JjR31l8ueQKBgQDkO2oC8gi6vQDcx/CX\nZ23x2ZUyar6i0BQ8eJFAEN+IiUapEeCVazuxJSt4RjYfwSa/p117jdZGEWD0GxMC\n+iAXlc5LlrrWs4MWUc0AHTgXna28/vii3ltcsI0AjWMqaybhBTTNbMFa2/fV2OX2\nUimuFyBWbzVc3Zb9KAG4Y7OmJQKBgQC5324IjXPq5oH8UWZTdJPuO2cgRsvKmR/r\n9zl4loRjkS7FiOMfzAgUiXfH9XCnvwXMqJpuMw2PEUjUT+OyWjJONEK4qGFJkbN5\n3ykc7p5V7iPPc7Zxj4mFvJ1xjkcj+i5LY8Me+gL5mGIrJ2j8hbuv7f+PWIauyjnp\nNx/0GVFRuQKBgGNT4D1L7LSokPmFIpYh811wHliE0Fa3TDdNGZnSPhaD9/aYyy78\nLkxYKuT7WY7UVvLN+gdNoVV5NsLGDa4cAV+CWPfYr5PFKGXMT/Wewcy1WOmJ5des\nAgMC6zq0TdYmMBN6WpKUpEnQtbmh3eMnuvADLJWxbH3wCkg+4xDGg2bpAoGAYRNk\nMGtQQzqoYNNSkfus1xuHPMA8508Z8O9pwKU795R3zQs1NAInpjI1sOVrNPD7Ymwc\nW7mmNzZbxycCUL/yzg1VW4P1a6sBBYGbw1SMtWxun4ZbnuvMc2CTCh+43/1l+FHe\nMmt46kq/2rH2jwx5feTbOE6P6PINVNRJh/9BDWECgYEAsCWcH9D3cI/QDeLG1ao7\nrE2NcknP8N783edM07Z/zxWsIsXhBPY3gjHVz2LDl+QHgPWhGML62M0ja/6SsJW3\nYvLLIc82V7eqcVJTZtaFkuht68qu/Jn1ezbzJMJ4YXDYo1+KFi+2CAGR06QILb+I\nlUtj+/nH3HDQjM4ltYfTPUg=\n-----END PRIVATE KEY-----\n",
      "client_email": "foo-email@foo-project.iam.gserviceaccount.com",
      "client_id": "100000000000000000001",
      "auth_uri": "https://accounts.google.com/o/oauth2/auth",
      "token_uri": "https://oauth2.googleapis.com/token",
      "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
      "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/foo-email%40foo-project.iam.gserviceaccount.com"
})""";

class ServiceAccountCredentialsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    MockHttpRequestBuilder::mock =
        std::make_shared<MockHttpRequestBuilder::Impl>();
  }
  void TearDown() override { MockHttpRequestBuilder::mock.reset(); }
};

struct FakeClock : public std::chrono::system_clock {
 public:
  // gmock doesn't easily allow copying mock objects, but we require this
  // struct to be copyable. So while the usual approach would be mocking this
  // method and defining its return value in each test, we instead override
  // this method and hard-code the return value for all instances.
  static std::chrono::system_clock::time_point now() {
    return std::chrono::system_clock::from_time_t(
        static_cast<std::time_t>(kFixedJwtTimestamp));
  }
};

/// @test Verify that we can create service account credentials from a keyfile.
TEST_F(ServiceAccountCredentialsTest,
       RefreshingSendsCorrectRequestBodyAndParsesResponse) {
  auto mock_request = std::make_shared<MockHttpRequest::Impl>();
  std::string response = R"""({
      "token_type": "Type",
      "access_token": "access-token-value",
      "expires_in": 1234
  })""";
  EXPECT_CALL(*mock_request, MakeRequest(_))
      .WillOnce(Invoke([response](std::string const& payload) {
        EXPECT_THAT(payload, HasSubstr(kExpectedAssertionParam));
        // Hard-coded in this order in ServiceAccountCredentials class.
        EXPECT_THAT(payload,
                    HasSubstr(std::string("grant_type=") + kGrantParamEscaped));
        return storage::internal::HttpResponse{200, response, {}};
      }));

  auto mock_builder = MockHttpRequestBuilder::mock;
  EXPECT_CALL(*mock_builder, BuildRequest()).WillOnce(Invoke([mock_request] {
    MockHttpRequest result;
    result.mock = mock_request;
    return result;
  }));

  std::string expected_header =
      "Content-Type: application/x-www-form-urlencoded";
  EXPECT_CALL(*mock_builder, AddHeader(StrEq(expected_header)));
  EXPECT_CALL(*mock_builder, Constructor(kGoogleOAuthRefreshEndpoint)).Times(1);
  EXPECT_CALL(*mock_builder, MakeEscapedString(An<std::string const&>()))
      .WillRepeatedly(
          Invoke([](std::string const& s) -> std::unique_ptr<char[]> {
            EXPECT_EQ(kGrantParamUnescaped, s);
            auto t =
                std::unique_ptr<char[]>(new char[sizeof(kGrantParamEscaped)]);
            std::copy(kGrantParamEscaped,
                      kGrantParamEscaped + sizeof(kGrantParamEscaped), t.get());
            return t;
          }));

  ServiceAccountCredentials<MockHttpRequestBuilder, FakeClock> credentials(
      kJsonKeyfileContents);

  // Calls Refresh to obtain the access token for our authorization header.
  EXPECT_EQ("Authorization: Type access-token-value",
            credentials.AuthorizationHeader());
}

/// @test Verify that we refresh service account credentials appropriately.
TEST_F(ServiceAccountCredentialsTest,
       RefreshCalledOnlyWhenAccessTokenIsMissingOrInvalid) {
  // Prepare two responses, the first one is used but becomes immediately
  // expired, resulting in another refresh next time the caller tries to get
  // an authorization header.
  std::string r1 = R"""({
    "token_type": "Type",
    "access_token": "access-token-r1",
    "expires_in": 0
})""";
  std::string r2 = R"""({
    "token_type": "Type",
    "access_token": "access-token-r2",
    "expires_in": 1000
})""";
  auto mock_request = std::make_shared<MockHttpRequest::Impl>();
  EXPECT_CALL(*mock_request, MakeRequest(_))
      .WillOnce(Return(storage::internal::HttpResponse{200, r1, {}}))
      .WillOnce(Return(storage::internal::HttpResponse{200, r2, {}}));

  // Now setup the builder to return those responses.
  auto mock_builder = MockHttpRequestBuilder::mock;
  auto request_mocker = [mock_request] {
    MockHttpRequest request;
    request.mock = mock_request;
    return request;
  };
  EXPECT_CALL(*mock_builder, BuildRequest())
      .WillOnce(Invoke(request_mocker))
      .WillOnce(Invoke(request_mocker));
  EXPECT_CALL(*mock_builder, AddHeader(An<std::string const&>())).Times(2);
  EXPECT_CALL(*mock_builder, Constructor(kGoogleOAuthRefreshEndpoint)).Times(2);
  EXPECT_CALL(*mock_builder, MakeEscapedString(An<std::string const&>()))
      .WillRepeatedly(
          Invoke([](std::string const& s) -> std::unique_ptr<char[]> {
            EXPECT_EQ(kGrantParamUnescaped, s);
            auto t =
                std::unique_ptr<char[]>(new char[sizeof(kGrantParamEscaped)]);
            std::copy(kGrantParamEscaped,
                      kGrantParamEscaped + sizeof(kGrantParamEscaped), t.get());
            return t;
          }));

  ServiceAccountCredentials<MockHttpRequestBuilder> credentials(
      kJsonKeyfileContents);
  // Calls Refresh to obtain the access token for our authorization header.
  EXPECT_EQ("Authorization: Type access-token-r1",
            credentials.AuthorizationHeader());
  // Token is expired, resulting in another call to Refresh.
  EXPECT_EQ("Authorization: Type access-token-r2",
            credentials.AuthorizationHeader());
  // Token still valid; should return cached token instead of calling Refresh.
  EXPECT_EQ("Authorization: Type access-token-r2",
            credentials.AuthorizationHeader());
}

}  // namespace
}  // namespace oauth2
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
