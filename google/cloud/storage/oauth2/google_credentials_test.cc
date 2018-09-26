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

#include "google/cloud/storage/oauth2/google_credentials.h"
#include "google/cloud/internal/setenv.h"
#include "google/cloud/testing_util/environment_variable_restore.h"
#include <gmock/gmock.h>
#include <fstream>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace oauth2 {
namespace {
using ::google::cloud::internal::SetEnv;
using ::google::cloud::internal::UnsetEnv;
using ::google::cloud::testing_util::EnvironmentVariableRestore;

char const VAR_NAME[] = "GOOGLE_APPLICATION_CREDENTIALS";

class GoogleCredentialsTest : public ::testing::Test {
 public:
  GoogleCredentialsTest()
      : home_(internal::kGoogleAdcHomeVar),
        override_variable_("GOOGLE_APPLICATION_CREDENTIALS") {}

 protected:
  void SetUp() override {
    home_.SetUp();
    override_variable_.SetUp();
  }
  void TearDown() override {
    override_variable_.TearDown();
    home_.TearDown();
  }

 protected:
  EnvironmentVariableRestore home_;
  EnvironmentVariableRestore override_variable_;
};

// TODO: Move to its own file.
/// @test Verify `AnonymousCredentials` works as expected.
TEST_F(GoogleCredentialsTest, Insecure) {
  AnonymousCredentials credentials;
  EXPECT_EQ("", credentials.AuthorizationHeader());
}

/// @test Verify that the application can override the default credentials.
TEST_F(GoogleCredentialsTest, EnvironmentVariableSet) {
  SetEnv("GOOGLE_APPLICATION_CREDENTIALS", "/foo/bar/baz");
  std::string actual = internal::GoogleAdcFilePath();
  EXPECT_EQ("/foo/bar/baz", actual);
}

/// @test Verify that the file path works as expected when using HOME.
TEST_F(GoogleCredentialsTest, HomeSet) {
  UnsetEnv("GOOGLE_APPLICATION_CREDENTIALS");
  char const* home = internal::kGoogleAdcHomeVar;
  SetEnv(home, "/foo/bar/baz");
  std::string actual = internal::GoogleAdcFilePath();
  using testing::HasSubstr;
  EXPECT_THAT(actual, HasSubstr("/foo/bar/baz"));
  EXPECT_THAT(actual, HasSubstr(".json"));
}

/// @test Verify that the service account file path fails when HOME is not set.
TEST_F(GoogleCredentialsTest, HomeNotSet) {
  UnsetEnv("GOOGLE_APPLICATION_CREDENTIALS");
  char const* home = internal::kGoogleAdcHomeVar;
  UnsetEnv(home);
#if GOOGLE_CLOUD_CPP_HAVE_EXCEPTIONS
  EXPECT_THROW(internal::GoogleAdcFilePath(), std::runtime_error);
#else
  EXPECT_DEATH_IF_SUPPORTED(internal::GoogleAdcFilePath(),
                            "exceptions are disabled");
#endif  // GOOGLE_CLOUD_CPP_HAVE_EXCEPTIONS
}

/**
 * @test Verify `GoogleDefaultCredentials()` loads authorized user credentials.
 *
 * This test only verifies the right type of object is created, the unit tests
 * for `AuthorizedUserCredentials` already check that once loaded the class
 * works correctly. Testing here would be redundant. Furthermore, calling
 * `AuthorizationHeader()` initiates the key verification workflow, that
 * requires valid keys and contacting Google's production servers, and would
 * make this an integration test.
 */
TEST_F(GoogleCredentialsTest, LoadValidAuthorizedUserCredentials) {
  char const filename[] = "authorized-user.json";
  std::ofstream os(filename);
  std::string contents_str = R"""({
  "client_id": "test-invalid-test-invalid.apps.googleusercontent.com",
  "client_secret": "invalid-invalid-invalid",
  "refresh_token": "1/test-test-test",
  "type": "authorized_user"
})""";
  os << contents_str;
  os.close();
  SetEnv(VAR_NAME, filename);

  // Test that the service account credentials are loaded as the default when
  // specified via the well known environment variable.
  auto credentials = GoogleDefaultCredentials();
  // Need to create a temporary for the pointer because clang-tidy warns about
  // using expressions with (potential) side-effects inside typeid().
  auto ptr = credentials.get();
  EXPECT_EQ(typeid(*ptr), typeid(AuthorizedUserCredentials<>));

  // Test that the authorized user credentials are loaded from a file.
  credentials = CreateAuthorizedUserCredentialsFromJsonFilePath(filename);
  ptr = credentials.get();
  EXPECT_EQ(typeid(*ptr), typeid(AuthorizedUserCredentials<>));

  // Test that the authorized user credentials are loaded from a string
  // representing JSON contents.
  credentials = CreateAuthorizedUserCredentialsFromJsonContents(contents_str);
  ptr = credentials.get();
  EXPECT_EQ(typeid(*ptr), typeid(AuthorizedUserCredentials<>));
}

/**
 * @test Verify `GoogleDefaultCredentials()` loads service account credentials.
 *
 * This test only verifies the right type of object is created, the unit tests
 * for `ServiceAccountCredentials` already check that once loaded the class
 * works correctly. Testing here would be redundant. Furthermore, calling
 * `AuthorizationHeader()` initiates the key verification workflow, that
 * requires valid keys and contacting Google's production servers, and would
 * make this an integration test.
 */
TEST_F(GoogleCredentialsTest, LoadValidServiceAccountCredentials) {
  char const filename[] = "service-account.json";
  std::ofstream os(filename);
  std::string contents_str = R"""({
    "type": "service_account",
    "project_id": "foo-project",
    "private_key_id": "a1a111aa1111a11a11a11aa111a111a1a1111111",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCltiF2oP3KJJ+S\ntTc1McylY+TuAi3AdohX7mmqIjd8a3eBYDHs7FlnUrFC4CRijCr0rUqYfg2pmk4a\n6TaKbQRAhWDJ7XD931g7EBvCtd8+JQBNWVKnP9ByJUaO0hWVniM50KTsWtyX3up/\nfS0W2R8Cyx4yvasE8QHH8gnNGtr94iiORDC7De2BwHi/iU8FxMVJAIyDLNfyk0hN\neheYKfIDBgJV2v6VaCOGWaZyEuD0FJ6wFeLybFBwibrLIBE5Y/StCrZoVZ5LocFP\nT4o8kT7bU6yonudSCyNMedYmqHj/iF8B2UN1WrYx8zvoDqZk0nxIglmEYKn/6U7U\ngyETGcW9AgMBAAECggEAC231vmkpwA7JG9UYbviVmSW79UecsLzsOAZnbtbn1VLT\nPg7sup7tprD/LXHoyIxK7S/jqINvPU65iuUhgCg3Rhz8+UiBhd0pCH/arlIdiPuD\n2xHpX8RIxAq6pGCsoPJ0kwkHSw8UTnxPV8ZCPSRyHV71oQHQgSl/WjNhRi6PQroB\nSqc/pS1m09cTwyKQIopBBVayRzmI2BtBxyhQp9I8t5b7PYkEZDQlbdq0j5Xipoov\n9EW0+Zvkh1FGNig8IJ9Wp+SZi3rd7KLpkyKPY7BK/g0nXBkDxn019cET0SdJOHQG\nDiHiv4yTRsDCHZhtEbAMKZEpku4WxtQ+JjR31l8ueQKBgQDkO2oC8gi6vQDcx/CX\nZ23x2ZUyar6i0BQ8eJFAEN+IiUapEeCVazuxJSt4RjYfwSa/p117jdZGEWD0GxMC\n+iAXlc5LlrrWs4MWUc0AHTgXna28/vii3ltcsI0AjWMqaybhBTTNbMFa2/fV2OX2\nUimuFyBWbzVc3Zb9KAG4Y7OmJQKBgQC5324IjXPq5oH8UWZTdJPuO2cgRsvKmR/r\n9zl4loRjkS7FiOMfzAgUiXfH9XCnvwXMqJpuMw2PEUjUT+OyWjJONEK4qGFJkbN5\n3ykc7p5V7iPPc7Zxj4mFvJ1xjkcj+i5LY8Me+gL5mGIrJ2j8hbuv7f+PWIauyjnp\nNx/0GVFRuQKBgGNT4D1L7LSokPmFIpYh811wHliE0Fa3TDdNGZnSPhaD9/aYyy78\nLkxYKuT7WY7UVvLN+gdNoVV5NsLGDa4cAV+CWPfYr5PFKGXMT/Wewcy1WOmJ5des\nAgMC6zq0TdYmMBN6WpKUpEnQtbmh3eMnuvADLJWxbH3wCkg+4xDGg2bpAoGAYRNk\nMGtQQzqoYNNSkfus1xuHPMA8508Z8O9pwKU795R3zQs1NAInpjI1sOVrNPD7Ymwc\nW7mmNzZbxycCUL/yzg1VW4P1a6sBBYGbw1SMtWxun4ZbnuvMc2CTCh+43/1l+FHe\nMmt46kq/2rH2jwx5feTbOE6P6PINVNRJh/9BDWECgYEAsCWcH9D3cI/QDeLG1ao7\nrE2NcknP8N783edM07Z/zxWsIsXhBPY3gjHVz2LDl+QHgPWhGML62M0ja/6SsJW3\nYvLLIc82V7eqcVJTZtaFkuht68qu/Jn1ezbzJMJ4YXDYo1+KFi+2CAGR06QILb+I\nlUtj+/nH3HDQjM4ltYfTPUg=\n-----END PRIVATE KEY-----\n",
    "client_email": "foo-email@foo-project.iam.gserviceaccount.com",
    "client_id": "100000000000000000001",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://accounts.google.com/o/oauth2/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/foo-email%40foo-project.iam.gserviceaccount.com"
})""";
  os << contents_str;
  os.close();
  SetEnv(VAR_NAME, filename);

  // Test that the service account credentials are loaded as the default when
  // specified via the well known environment variable.
  auto credentials = GoogleDefaultCredentials();
  // Need to create a temporary for the pointer because clang-tidy warns about
  // using expressions with (potential) side-effects inside typeid().
  auto ptr = credentials.get();
  EXPECT_EQ(typeid(*ptr), typeid(ServiceAccountCredentials<>));

  // Test that the service account credentials are loaded from a file.
  credentials = CreateServiceAccountCredentialsFromJsonFilePath(filename);
  ptr = credentials.get();
  EXPECT_EQ(typeid(*ptr), typeid(ServiceAccountCredentials<>));

  // Test that the service account credentials are loaded from a string
  // representing JSON contents.
  credentials = CreateServiceAccountCredentialsFromJsonContents(contents_str);
  ptr = credentials.get();
  EXPECT_EQ(typeid(*ptr), typeid(ServiceAccountCredentials<>));
}

TEST_F(GoogleCredentialsTest, LoadValidAnonymousCredentials) {
  auto credentials = CreateAnonymousCredentials();
  // Need to create a temporary for the pointer because clang-tidy warns about
  // using expressions with (potential) side-effects inside typeid().
  auto ptr = credentials.get();
  EXPECT_EQ(typeid(*ptr), typeid(AnonymousCredentials));
}

}  // namespace
}  // namespace oauth2
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
