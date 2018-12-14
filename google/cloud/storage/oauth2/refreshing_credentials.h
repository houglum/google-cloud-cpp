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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_OAUTH2_REFRESHING_CREDENTIALS_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_OAUTH2_REFRESHING_CREDENTIALS_H_

#include "google/cloud/storage/oauth2/credentials.h"
#include "google/cloud/storage/status.h"
#include <chrono>
#include <mutex>
#include <string>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace oauth2 {
/**
 * Interface for OAuth 2.0 credentials that can be refreshed.
 *
 * This interface provides an implementation of the `AuthorizationHeader()`
 * method that allows subclasses to read and write an access token (and
 * associated attributes) atomically, refreshing it if needed. Subclasses must
 * define their own `Refresh()` method, which is used by
 * `AuthorizationHeader()` to update the `authorization_header_` and
 * `expiration_time_` members.
 *
 * @note This assumes that the `Refresh()` method is called only from within
 * `AuthorizationHeader()`, when the instance's mutex `mu_` is held. If a
 * subclass defines additional class members that can be updated inside of
 * its `Refresh()` method, or provides additional functionality to access the
 * members defined in this class, that subclass is responsible for ensuring
 * those accesses are performed with the mutex held.
 */
class RefreshingCredentials : public Credentials {
 public:
  virtual ~RefreshingCredentials() = default;

  std::pair<storage::Status, std::string> AuthorizationHeader() override {
    std::unique_lock<std::mutex> lock(mu_);

    if (IsValid()) {
      return std::make_pair(storage::Status(), authorization_header_);
    }

    storage::Status status = Refresh();
    return std::make_pair(status,
                          status.ok() ? authorization_header_ : std::string{});
  }

 protected:
  bool IsExpired() {
    auto now = std::chrono::system_clock::now();
    return now > (expiration_time_ - GoogleOAuthAccessTokenExpirationSlack());
  }

  bool IsValid() {
    return not authorization_header_.empty() and not IsExpired();
  }

  virtual storage::Status Refresh() = 0;

  // This mutex should be held when reading or writing to any class members that
  // can change as a result of a Refresh() call.
  std::mutex mu_;
  std::string authorization_header_;
  std::chrono::system_clock::time_point expiration_time_;
};

}  // namespace oauth2
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_OAUTH2_REFRESHING_CREDENTIALS_H_
