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

#include "google/cloud/internal/throw_delegate.h"
#include "google/cloud/storage/oauth2/credentials.h"
#include "google/cloud/storage/version.h"
#include <mutex>
#include <sstream>
#include <string>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace oauth2 {

/**
 * Base class for a credential that must periodically refresh itself.
 */
class RefreshingCredentials : public Credentials {
 public:
  virtual ~RefreshingCredentials() = default;

  std::string AuthorizationHeader() override {
    // TODO: Show Status details upon failure, once Refresh returns a Status.
    auto token_ready = RefreshIfNeeded();
    if (not token_ready) {
      std::ostringstream os;
      os << "Failed to obtain an access token.";
      google::cloud::internal::RaiseRuntimeError(os.str());
    }
    return "Authorization: " + token_type_ + " " + access_token_;
  }

 protected:
  /**
   * Return whether this credential's access token should be considered expired.
   */
  virtual bool IsExpired() = 0;

  /**
   * Request a new access token from the authorization endpoint.
   */
  // TODO: Make this return a Status instead of a bool?
  virtual bool Refresh() = 0;

  /**
   * Return whether this credential has a valid access token. This should be
   * used as the predicate for whether or not this credential should be
   * refreshed to obtain a new access token.
   */
  bool IsValid() { return not access_token_.empty() and not IsExpired(); }

  // TODO: When Refresh() returns a Status instead, also return a Status here,
  // using OK status if credential is already valid.
  // - Is this correct? If the underlying Status is not OK, Refresh() should
  //   probably die or throw an exception, meaning handling it here would be
  //   unnecessary... unless we want to enable returning a Status from Refresh()
  //   and handling the failure in its caller? Would this make testing easier?
  //   Probably need to write tests before being able to answer this.
  // TODO: Does this really need to be overridden in each child class? It looks
  // like this is going to be the same exact logic in each credential class.
  bool RefreshIfNeeded() {
    if (IsValid()) {
      return true;
    }
    std::unique_lock<std::mutex> ulock(mu_);
    // Note that if multiple threads tried to request an authorization header
    // at the same time and it had expired, they would all attempt to grab the
    // lock and perform a token refresh. To avoid this and ensure only the first
    // call results in a refresh, we grab the lock, then first check if the
    // credential is valid (i.e. if another thread already refreshed it) before
    // refreshing.
    if (IsValid()) {
      return true;
    }
    return Refresh();
  }

  std::string access_token_;
  std::string token_type_;
  /// Lock used to coordinate credential refresh attempts, which should normally
  /// only happen after the credential has become invalid. This lock should be
  /// obtained before calling `Refresh()`.
  std::mutex mu_;
};

}  // namespace oauth2
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_OAUTH2_REFRESHING_CREDENTIALS_H_
