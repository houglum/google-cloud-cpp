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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_CURL_CLIENT_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_CURL_CLIENT_H_

#include "google/cloud/storage/internal/curl_handle_factory.h"
#include "google/cloud/storage/internal/raw_client.h"
#include "google/cloud/storage/oauth2/credentials.h"
#include <mutex>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
class CurlRequestBuilder;

/**
 * Implements the low-level RPCs to Google Cloud Storage using libcurl.
 *
 * TODO(#717) - document the CurlRequest interface as a concept.
 */
class CurlClient : public RawClient {
 public:
  // TODO(#937) - use the client options to set the buffer size.
  // This value is mostly arbitrary. It is big enough to fit the typical socket
  // buffer, but not so large that we worry about memory utilization.
  static constexpr std::size_t kDefaultBufferSize = 128 * 1024;

  explicit CurlClient(std::shared_ptr<storage::oauth2::Credentials> credentials)
      : CurlClient(ClientOptions(std::move(credentials))) {}

  explicit CurlClient(ClientOptions options);

  CurlClient(CurlClient const& rhs) = delete;
  CurlClient(CurlClient&& rhs) = delete;
  CurlClient& operator=(CurlClient const& rhs) = delete;
  CurlClient& operator=(CurlClient&& rhs) = delete;

  using LockFunction =
      std::function<void(CURL*, curl_lock_data, curl_lock_access)>;
  using UnlockFunction = std::function<void(CURL*, curl_lock_data)>;

  ClientOptions const& client_options() const override { return options_; }

  std::pair<Status, ListBucketsResponse> ListBuckets(
      ListBucketsRequest const& request) override;
  std::pair<Status, BucketMetadata> CreateBucket(
      CreateBucketRequest const& request) override;
  std::pair<Status, BucketMetadata> GetBucketMetadata(
      GetBucketMetadataRequest const& request) override;
  std::pair<Status, EmptyResponse> DeleteBucket(
      DeleteBucketRequest const&) override;
  std::pair<Status, BucketMetadata> UpdateBucket(
      UpdateBucketRequest const& request) override;
  std::pair<Status, BucketMetadata> PatchBucket(
      PatchBucketRequest const& request) override;
  std::pair<Status, IamPolicy> GetBucketIamPolicy(
      GetBucketIamPolicyRequest const& request) override;
  std::pair<Status, IamPolicy> SetBucketIamPolicy(
      SetBucketIamPolicyRequest const& request) override;
  std::pair<Status, TestBucketIamPermissionsResponse> TestBucketIamPermissions(
      TestBucketIamPermissionsRequest const& request) override;

  std::pair<Status, ObjectMetadata> InsertObjectMedia(
      InsertObjectMediaRequest const& request) override;
  std::pair<Status, ObjectMetadata> GetObjectMetadata(
      GetObjectMetadataRequest const& request) override;
  std::pair<Status, std::unique_ptr<ObjectReadStreambuf>> ReadObject(
      ReadObjectRangeRequest const&) override;
  std::pair<Status, std::unique_ptr<ObjectWriteStreambuf>> WriteObject(
      InsertObjectStreamingRequest const&) override;
  std::pair<Status, ListObjectsResponse> ListObjects(
      ListObjectsRequest const& request) override;
  std::pair<Status, EmptyResponse> DeleteObject(
      DeleteObjectRequest const& request) override;
  std::pair<Status, ObjectMetadata> UpdateObject(
      UpdateObjectRequest const& request) override;
  std::pair<Status, ObjectMetadata> PatchObject(
      PatchObjectRequest const& request) override;
  std::pair<Status, ObjectMetadata> ComposeObject(
      ComposeObjectRequest const& request) override;

  std::pair<Status, ListBucketAclResponse> ListBucketAcl(
      ListBucketAclRequest const& request) override;
  std::pair<Status, ObjectMetadata> CopyObject(
      CopyObjectRequest const& request) override;
  std::pair<Status, BucketAccessControl> CreateBucketAcl(
      CreateBucketAclRequest const&) override;
  std::pair<Status, BucketAccessControl> GetBucketAcl(
      GetBucketAclRequest const&) override;
  std::pair<Status, EmptyResponse> DeleteBucketAcl(
      DeleteBucketAclRequest const&) override;
  std::pair<Status, BucketAccessControl> UpdateBucketAcl(
      UpdateBucketAclRequest const&) override;
  std::pair<Status, BucketAccessControl> PatchBucketAcl(
      PatchBucketAclRequest const&) override;

  std::pair<Status, ListObjectAclResponse> ListObjectAcl(
      ListObjectAclRequest const& request) override;
  std::pair<Status, ObjectAccessControl> CreateObjectAcl(
      CreateObjectAclRequest const&) override;
  std::pair<Status, EmptyResponse> DeleteObjectAcl(
      DeleteObjectAclRequest const&) override;
  std::pair<Status, ObjectAccessControl> GetObjectAcl(
      GetObjectAclRequest const&) override;
  std::pair<Status, ObjectAccessControl> UpdateObjectAcl(
      UpdateObjectAclRequest const&) override;
  std::pair<Status, ObjectAccessControl> PatchObjectAcl(
      PatchObjectAclRequest const&) override;
  std::pair<Status, RewriteObjectResponse> RewriteObject(
      RewriteObjectRequest const&) override;

  std::pair<Status, ListDefaultObjectAclResponse> ListDefaultObjectAcl(
      ListDefaultObjectAclRequest const& request) override;
  std::pair<Status, ObjectAccessControl> CreateDefaultObjectAcl(
      CreateDefaultObjectAclRequest const&) override;
  std::pair<Status, EmptyResponse> DeleteDefaultObjectAcl(
      DeleteDefaultObjectAclRequest const&) override;
  std::pair<Status, ObjectAccessControl> GetDefaultObjectAcl(
      GetDefaultObjectAclRequest const&) override;
  std::pair<Status, ObjectAccessControl> UpdateDefaultObjectAcl(
      UpdateDefaultObjectAclRequest const&) override;
  std::pair<Status, ObjectAccessControl> PatchDefaultObjectAcl(
      PatchDefaultObjectAclRequest const&) override;

  std::pair<Status, ServiceAccount> GetServiceAccount(
      GetProjectServiceAccountRequest const&) override;

  std::pair<Status, ListNotificationsResponse> ListNotifications(
      ListNotificationsRequest const&) override;
  std::pair<Status, NotificationMetadata> CreateNotification(
      CreateNotificationRequest const&) override;
  std::pair<Status, NotificationMetadata> GetNotification(
      GetNotificationRequest const&) override;
  std::pair<Status, EmptyResponse> DeleteNotification(
      DeleteNotificationRequest const&) override;

  void LockShared();
  void UnlockShared();

 private:
  /// Applies the common configuration parameters to @p builder.
  template <typename Request>
  void SetupBuilder(CurlRequestBuilder& builder, Request const& request,
                    char const* method);

  std::pair<Status, ObjectMetadata> InsertObjectMediaXml(
      InsertObjectMediaRequest const& request);
  std::pair<Status, std::unique_ptr<ObjectReadStreambuf>> ReadObjectXml(
      ReadObjectRangeRequest const& request);
  std::pair<Status, std::unique_ptr<ObjectWriteStreambuf>> WriteObjectXml(
      InsertObjectStreamingRequest const& request);

  ClientOptions options_;
  std::string storage_endpoint_;
  std::string upload_endpoint_;
  std::string xml_upload_endpoint_;
  std::string xml_download_endpoint_;

  std::mutex mu_;
  CurlShare share_ /* GUARDED_BY(mu_) */;

  // The factories must be listed *after* the CurlShare. libcurl keeps a
  // usage count on each CURLSH* handle, which is only released once the CURL*
  // handle is *closed*. So we want the order of destruction to be (1)
  // factories, as that will delete all the CURL* handles, and then (2) CURLSH*.
  // To guarantee this order just list the members in the opposite order.
  std::shared_ptr<CurlHandleFactory> storage_factory_;
  std::shared_ptr<CurlHandleFactory> upload_factory_;
  std::shared_ptr<CurlHandleFactory> xml_upload_factory_;
  std::shared_ptr<CurlHandleFactory> xml_download_factory_;
};

}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_CURL_CLIENT_H_
