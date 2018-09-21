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

#include "google/cloud/internal/throw_delegate.h"
#include "google/cloud/storage/oauth2/credentials.h"
#include "google/cloud/storage/version.h"
#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <utility>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace oauth2 {

namespace internal {

std::string GoogleAdcFilePath() {
  auto override_value = std::getenv("GOOGLE_APPLICATION_CREDENTIALS");
  if (override_value != nullptr) {
    return std::string(override_value);
  }
  auto adc_path_root = std::getenv(kGoogleAdcHomeVar);
  if (adc_path_root == nullptr) {
    // TODO: When adding GCE credentials, cover that edge case here.
    std::ostringstream os;
    os << "The " << kGoogleAdcHomeVar << "environment variable is not set. "
       << "Cannot determine the default path for service account credentials.";
    google::cloud::internal::RaiseRuntimeError(os.str());
  }
  return std::string(adc_path_root) + kGoogleAdcWellKnownPathSuffix;
}

}  // namespace internal

std::shared_ptr<Credentials> GoogleDefaultCredentials() {
  auto path = internal::GoogleAdcFilePath();
  std::ifstream is(path);
  std::string contents(std::istreambuf_iterator<char>{is}, {});

  auto credentials_json = storage::internal::nl::json::parse(contents);
  std::string type = credentials_json["type"];
  if (type == "authorized_user") {
    return std::make_shared<AuthorizedUserCredentials<>>(contents);
  }
  if (type == "service_account") {
    return std::make_shared<ServiceAccountCredentials<>>(contents);
  }
  google::cloud::internal::RaiseRuntimeError("Unsupported credential type (" +
                                             type + ")");
}

std::shared_ptr<AnonymousCredentials> CreateAnonymousCredentials() {
  return std::make_shared<AnonymousCredentials>();
}

std::shared_ptr<AuthorizedUserCredentials<>>
CreateAuthorizedUserCredentialsFromJsonFilePath(std::string path) {
  std::ifstream is(path);
  std::string contents(std::istreambuf_iterator<char>{is}, {});
  return CreateAuthorizedUserCredentialsFromJsonContents(contents);
}

std::shared_ptr<AuthorizedUserCredentials<>>
CreateAuthorizedUserCredentialsFromJsonContents(std::string contents) {
  return std::make_shared<AuthorizedUserCredentials<>>(contents);
}

std::shared_ptr<ServiceAccountCredentials<>>
CreateServiceAccountCredentialsFromJsonFilePath(std::string path) {
  std::ifstream is(path);
  std::string contents(std::istreambuf_iterator<char>{is}, {});
  return CreateServiceAccountCredentialsFromJsonContents(contents);
}

std::shared_ptr<ServiceAccountCredentials<>>
CreateServiceAccountCredentialsFromJsonContents(std::string contents) {
  return std::make_shared<ServiceAccountCredentials<>>(contents);
}

}  // namespace oauth2
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
