// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "google/cloud/storage/client.h"
#include "google/cloud/storage/oauth2/google_credentials.h"
#include <functional>
#include <iostream>
#include <map>
#include <sstream>

namespace {
struct Usage {
  std::string msg;
};

char const* ConsumeArg(int& argc, char* argv[]) {
  if (argc < 2) {
    return nullptr;
  }
  char const* result = argv[1];
  std::copy(argv + 2, argv + argc, argv + 1);
  argc--;
  return result;
}

std::string command_usage;

void PrintUsage(int argc, char* argv[], std::string const& msg) {
  std::string const cmd = argv[0];
  auto last_slash = std::string(cmd).find_last_of('/');
  auto program = cmd.substr(last_slash + 1);
  std::cerr << msg << "\nUsage: " << program << " <command> [arguments]\n\n"
            << "Commands:\n"
            << command_usage << std::endl;
}

void ListObjects(google::cloud::storage::Client client, int& argc,
                 char* argv[]) {
  if (argc < 2) {
    throw Usage{"list-objects <bucket-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  //! [list objects] [START storage_list_files]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name) {
    for (gcs::ObjectMetadata const& meta : client.ListObjects(bucket_name)) {
      std::cout << "bucket_name=" << meta.bucket()
                << ", object_name=" << meta.name() << std::endl;
    }
  }
  //! [list objects] [END storage_list_files]
  (std::move(client), bucket_name);
}

void InsertObject(google::cloud::storage::Client client, int& argc,
                  char* argv[]) {
  if (argc < 3) {
    throw Usage{
        "insert-object <bucket-name> <object-name> <object-contents (string)>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  auto contents = ConsumeArg(argc, argv);
  //! [insert object] [START storage_upload_file]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name,
     std::string contents) {
    gcs::ObjectMetadata meta =
        client.InsertObject(bucket_name, object_name, std::move(contents));
    std::cout << "The file was uploaded. The new object metadata is " << meta
              << std::endl;
  }
  //! [insert object] [END storage_upload_file]
  (std::move(client), bucket_name, object_name, contents);
}

void CopyObject(google::cloud::storage::Client client, int& argc,
                char* argv[]) {
  if (argc != 5) {
    throw Usage{
        "copy-object <source-bucket-name> <source-object-name>"
        " <destination-bucket-name> <destination-object-name>"};
  }
  auto source_bucket_name = ConsumeArg(argc, argv);
  auto source_object_name = ConsumeArg(argc, argv);
  auto destination_bucket_name = ConsumeArg(argc, argv);
  auto destination_object_name = ConsumeArg(argc, argv);
  //! [copy object]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string source_bucket_name,
     std::string source_object_name, std::string destination_bucket_name,
     std::string destination_object_name) {
    gcs::ObjectMetadata new_copy_meta = client.CopyObject(
        source_bucket_name, source_object_name, destination_bucket_name,
        destination_object_name, gcs::ObjectMetadata());
    std::cout << "Object copied. The full metadata after the copy is: "
              << new_copy_meta << std::endl;
  }
  //! [copy object]
  (std::move(client), source_bucket_name, source_object_name,
   destination_bucket_name, destination_object_name);
}

void CopyEncryptedObject(google::cloud::storage::Client client, int& argc,
                         char* argv[]) {
  if (argc != 6) {
    throw Usage{
        "copy-encrypted-object <source-bucket-name> <source-object-name>"
        " <destination-bucket-name> <destination-object-name>"
        " <encryption-key-base64>"};
  }
  auto source_bucket_name = ConsumeArg(argc, argv);
  auto source_object_name = ConsumeArg(argc, argv);
  auto destination_bucket_name = ConsumeArg(argc, argv);
  auto destination_object_name = ConsumeArg(argc, argv);
  auto key = ConsumeArg(argc, argv);
  //! [copy encrypted object]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string source_bucket_name,
     std::string source_object_name, std::string destination_bucket_name,
     std::string destination_object_name, std::string key_base64) {
    gcs::ObjectMetadata new_copy_meta = client.CopyObject(
        source_bucket_name, source_object_name, destination_bucket_name,
        destination_object_name, gcs::ObjectMetadata(),
        gcs::EncryptionKey::FromBase64Key(key_base64));
    std::cout << "Object copied. The full metadata after the copy is: "
              << new_copy_meta << std::endl;
  }
  //! [copy encrypted object]
  (std::move(client), source_bucket_name, source_object_name,
   destination_bucket_name, destination_object_name, key);
}

void GetObjectMetadata(google::cloud::storage::Client client, int& argc,
                       char* argv[]) {
  if (argc < 3) {
    throw Usage{"get-object-metadata <bucket-name> <object-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  //! [get object metadata] [START storage_get_metadata]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name) {
    gcs::ObjectMetadata meta =
        client.GetObjectMetadata(bucket_name, object_name);
    std::cout << "The metadata is " << meta << std::endl;
  }
  //! [get object metadata] [END storage_get_metadata]
  (std::move(client), bucket_name, object_name);
}

void ReadObject(google::cloud::storage::Client client, int& argc,
                char* argv[]) {
  if (argc < 2) {
    throw Usage{"read-object <bucket-name> <object-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  //! [read object]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name) {
    gcs::ObjectReadStream stream = client.ReadObject(bucket_name, object_name);
    int count = 0;
    while (not stream.eof()) {
      std::string line;
      std::getline(stream, line, '\n');
      ++count;
    }
    std::cout << "The object has " << count << " lines" << std::endl;
  }
  //! [read object]
  (std::move(client), bucket_name, object_name);
}

void DeleteObject(google::cloud::storage::Client client, int& argc,
                  char* argv[]) {
  if (argc < 2) {
    throw Usage{"delete-object <bucket-name> <object-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  //! [delete object] [START storage_delete_file]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name) {
    client.DeleteObject(bucket_name, object_name);
    std::cout << "Deleted " << object_name << " in bucket " << bucket_name
              << std::endl;
  }
  //! [delete object] [END storage_delete_file]
  (std::move(client), bucket_name, object_name);
}

void WriteObject(google::cloud::storage::Client client, int& argc,
                 char* argv[]) {
  if (argc < 3) {
    throw Usage{
        "write-object <bucket-name> <object-name> <target-object-line-count>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  auto desired_line_count = std::stol(ConsumeArg(argc, argv));

  //! [write object]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name,
     long desired_line_count) {
    std::string const text = "Lorem ipsum dolor sit amet";
    gcs::ObjectWriteStream stream =
        client.WriteObject(bucket_name, object_name);

    for (int lineno = 0; lineno != desired_line_count; ++lineno) {
      // Add 1 to the counter, because it is conventional to number lines
      // starting at 1.
      stream << (lineno + 1) << ": " << text << "\n";
    }

    gcs::ObjectMetadata meta = stream.Close();
    std::cout << "The resulting object size is: " << meta.size() << std::endl;
  }
  //! [write object]
  (std::move(client), bucket_name, object_name, desired_line_count);
}

void UpdateObjectMetadata(google::cloud::storage::Client client, int& argc,
                          char* argv[]) {
  if (argc != 5) {
    throw Usage{
        "update-object-metadata <bucket-name> <object-name> <key> <value>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  auto key = ConsumeArg(argc, argv);
  auto value = ConsumeArg(argc, argv);
  //! [update object metadata] [START storage_set_metadata]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name,
     std::string key, std::string value) {
    gcs::ObjectMetadata meta =
        client.GetObjectMetadata(bucket_name, object_name);
    gcs::ObjectMetadata desired = meta;
    desired.mutable_metadata().emplace(key, value);
    gcs::ObjectMetadata updated = client.UpdateObject(
        bucket_name, object_name, desired, gcs::IfMatchEtag(meta.etag()));
    std::cout << "Object updated. The full metadata after the update is: "
              << updated << std::endl;
  }
  //! [update object metadata] [END storage_set_metadata]
  (std::move(client), bucket_name, object_name, key, value);
}

void PatchObjectDeleteMetadata(google::cloud::storage::Client client, int& argc,
                               char* argv[]) {
  if (argc != 4) {
    throw Usage{"update-object-metadata <bucket-name> <object-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  auto key = ConsumeArg(argc, argv);
  //! [patch object delete metadata]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name,
     std::string key) {
    gcs::ObjectMetadata original =
        client.GetObjectMetadata(bucket_name, object_name);
    gcs::ObjectMetadata updated = original;
    updated.mutable_metadata().erase(key);
    gcs::ObjectMetadata result =
        client.PatchObject(bucket_name, object_name, original, updated);
    std::cout << "Object updated. The full metadata after the update is: "
              << result << std::endl;
  }
  //! [patch object delete metadata]
  (std::move(client), bucket_name, object_name, key);
}

void PatchObjectContentType(google::cloud::storage::Client client, int& argc,
                            char* argv[]) {
  if (argc != 4) {
    throw Usage{
        "update-object-metadata <bucket-name> <object-name> <content-type>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  auto content_type = ConsumeArg(argc, argv);
  //! [patch object content type]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name,
     std::string content_type) {
    gcs::ObjectMetadata updated = client.PatchObject(
        bucket_name, object_name,
        gcs::ObjectMetadataPatchBuilder().SetContentType(content_type));
    std::cout << "Object updated. The full metadata after the update is: "
              << updated << std::endl;
  }
  //! [patch object content type]
  (std::move(client), bucket_name, object_name, content_type);
}

void MakeObjectPublic(google::cloud::storage::Client client, int& argc,
                      char* argv[]) {
  if (argc != 3) {
    throw Usage{"make-object-public <bucket-name> <object-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  //! [make object public] [START storage_make_public]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name) {
    gcs::ObjectMetadata updated = client.PatchObject(
        bucket_name, object_name, gcs::ObjectMetadataPatchBuilder(),
        gcs::PredefinedAcl::PublicRead());
    std::cout << "Object updated. The full metadata after the update is: "
              << updated << std::endl;
  }
  //! [make object public] [END storage_make_public]
  (std::move(client), bucket_name, object_name);
}

void ReadObjectUnauthenticated(google::cloud::storage::Client client, int& argc,
                               char* argv[]) {
  if (argc < 2) {
    throw Usage{"read-object-unauthenticated <bucket-name> <object-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  //! [read object unauthenticated]
  namespace gcs = google::cloud::storage;
  [](std::string bucket_name, std::string object_name) {
    // Create a client that does not authenticate with the server.
    gcs::Client client{gcs::oauth2::CreateAnonymousCredentials()};
    // Read an object, the object must have been made public.
    gcs::ObjectReadStream stream = client.ReadObject(bucket_name, object_name);
    int count = 0;
    while (not stream.eof()) {
      std::string line;
      std::getline(stream, line, '\n');
      ++count;
    }
    std::cout << "The object has " << count << " lines" << std::endl;
  }
  //! [read object unauthenticated]
  (bucket_name, object_name);
}

void GenerateEncryptionKey(google::cloud::storage::Client client, int& argc,
                           char* argv[]) {
  if (argc != 1) {
    throw Usage{"generate-encryption-key"};
  }
  //! [generate encryption key] [START generate_encryption_key_base64]
  // Create a pseudo-random number generator (PRNG), this is included for
  // demonstration purposes only. You should consult your security team about
  // best practices to initialize PRNG. In particular, you should verify that
  // the C++ library and operating system provide enough entropy to meet the
  // security policies in your organization.

  // Use the Mersenne-Twister Engine in this example:
  //   https://en.cppreference.com/w/cpp/numeric/random/mersenne_twister_engine
  // Any C++ PRNG can be used below, the choice is arbitrary.
  using GeneratorType = std::mt19937_64;

  // Create the default random device to fetch entropy.
  std::random_device rd;

  // Compute how much entropy we need to initialize the GeneratorType:
  constexpr auto kRequiredEntropyWords =
      GeneratorType::state_size *
      (GeneratorType::word_size / std::numeric_limits<unsigned int>::digits);

  // Capture the entropy bits into a vector.
  std::vector<unsigned long> entropy(kRequiredEntropyWords);
  std::generate(entropy.begin(), entropy.end(), [&rd] { return rd(); });

  // Create the PRNG with the fetched entropy.
  std::seed_seq seed(entropy.begin(), entropy.end());

  // initialized with enough entropy such that the encryption keys are not
  // predictable. Note that the default constructor for all the generators in
  // the C++ standard library produce predictable keys.
  std::mt19937_64 gen(seed);

  namespace gcs = google::cloud::storage;
  gcs::EncryptionKeyData data = gcs::CreateKeyFromGenerator(gen);

  std::cout << "Base64 encoded key = " << data.key << "\n"
            << "Base64 encoded SHA256 of key = " << data.sha256 << std::endl;
  //! [generate encryption key] [END generate_encryption_key_base64]
}

void WriteEncryptedObject(google::cloud::storage::Client client, int& argc,
                          char* argv[]) {
  if (argc != 4) {
    throw Usage{
        "write-encrypted-object <bucket-name> <object-name>"
        " <base64-encoded-aes256-key>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  auto base64_aes256_key = ConsumeArg(argc, argv);
  //! [insert encrypted object] [START storage_upload_encrypted_file]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name,
     std::string base64_aes256_key) {
    gcs::ObjectMetadata meta = client.InsertObject(
        bucket_name, object_name, "top secret",
        gcs::EncryptionKey::FromBase64Key(base64_aes256_key));
    std::cout << "The object was created. The new object metadata is " << meta
              << std::endl;
  }
  //! [insert encrypted object] [END storage_upload_encrypted_file]
  (std::move(client), bucket_name, object_name, base64_aes256_key);
}

void ReadEncryptedObject(google::cloud::storage::Client client, int& argc,
                         char* argv[]) {
  if (argc != 4) {
    throw Usage{
        "read-encrypted-object <bucket-name> <object-name>"
        " <base64-encoded-aes256-key>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  auto base64_aes256_key = ConsumeArg(argc, argv);
  //! [read encrypted object] [START storage_download_encrypted_file]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name,
     std::string base64_aes256_key) {
    gcs::ObjectReadStream stream =
        client.ReadObject(bucket_name, object_name,
                          gcs::EncryptionKey::FromBase64Key(base64_aes256_key));
    std::string data(std::istreambuf_iterator<char>{stream}, {});
    std::cout << "The object contents are: " << data << std::endl;
  }
  //! [read encrypted object] [END storage_download_encrypted_file]
  (std::move(client), bucket_name, object_name, base64_aes256_key);
}

void ComposeObject(google::cloud::storage::Client client, int& argc,
                   char* argv[]) {
  if (argc < 4) {
    throw Usage{
        "compose-object <bucket-name> <destination-object-name>"
        " <object_1> ..."};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto destination_object_name = ConsumeArg(argc, argv);
  std::vector<google::cloud::storage::ComposeSourceObject> compose_objects;
  while (argc > 1) {
    compose_objects.push_back({ConsumeArg(argc, argv)});
  }
  //! [compose object] [START storage_compose_file]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name,
     std::string destination_object_name,
     std::vector<gcs::ComposeSourceObject> compose_objects) {
    gcs::ObjectMetadata composed_object =
        client.ComposeObject(bucket_name, compose_objects,
                             destination_object_name, gcs::ObjectMetadata());
    std::cout << "Composed new object " << destination_object_name
              << " Metadata: " << composed_object << std::endl;
  }
  //! [compose object] [END storage_compose_file]
  (std::move(client), bucket_name, destination_object_name,
   std::move(compose_objects));
}

void ComposeObjectFromEncryptedObjects(google::cloud::storage::Client client,
                                       int& argc, char* argv[]) {
  if (argc < 5) {
    throw Usage{
        "compose-object-from-encrypted-objects <bucket-name>"
        " <destination-object-name> <base64-encoded-aes256-key>"
        " <object_1> ..."};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto destination_object_name = ConsumeArg(argc, argv);
  auto base64_aes256_key = ConsumeArg(argc, argv);
  std::vector<google::cloud::storage::ComposeSourceObject> compose_objects;
  while (argc > 1) {
    compose_objects.push_back({ConsumeArg(argc, argv)});
  }
  //! [compose object from encrypted objects]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name,
     std::string destination_object_name, std::string base64_aes256_key,
     std::vector<gcs::ComposeSourceObject> compose_objects) {
    gcs::ObjectMetadata composed_object = client.ComposeObject(
        bucket_name, compose_objects, destination_object_name,
        gcs::ObjectMetadata(),
        gcs::EncryptionKey::FromBase64Key(base64_aes256_key));
    std::cout << "Composed new object " << destination_object_name
              << " Metadata: " << composed_object << std::endl;
  }
  //! [compose object from encrypted objects]
  (std::move(client), bucket_name, destination_object_name, base64_aes256_key,
   std::move(compose_objects));
}

void WriteObjectWithKmsKey(google::cloud::storage::Client client, int& argc,
                           char* argv[]) {
  if (argc < 3) {
    throw Usage{
        "write-object-with-kms-key <bucket-name> <object-name>"
        " <kms-key-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  auto kms_key_name = ConsumeArg(argc, argv);

  //! [write object with kms key] [START storage_upload_with_kms_key]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name,
     std::string kms_key_name) {
    gcs::ObjectWriteStream stream = client.WriteObject(
        bucket_name, object_name, gcs::KmsKeyName(kms_key_name));

    // Line numbers start at 1.
    for (int lineno = 1; lineno <= 10; ++lineno) {
      stream << lineno << ": placeholder text for CMEK example.\n";
    }

    gcs::ObjectMetadata meta = stream.Close();
    std::cout << "The resulting object size is: " << meta.size() << std::endl;
  }
  //! [write object with kms key] [END storage_upload_with_kms_key]
  (std::move(client), bucket_name, object_name, kms_key_name);
}
}  // anonymous namespace

int main(int argc, char* argv[]) try {
  // Create a client to communicate with Google Cloud Storage.
  //! [create client]
  google::cloud::storage::Client client;
  //! [create client]

  using CommandType =
      std::function<void(google::cloud::storage::Client, int&, char*[])>;
  std::map<std::string, CommandType> commands = {
      {"list-objects", &ListObjects},
      {"insert-object", &InsertObject},
      {"copy-object", &CopyObject},
      {"copy-encrypted-object", &CopyEncryptedObject},
      {"get-object-metadata", &GetObjectMetadata},
      {"read-object", &ReadObject},
      {"delete-object", &DeleteObject},
      {"write-object", &WriteObject},
      {"update-object-metadata", &UpdateObjectMetadata},
      {"patch-object-delete-metadata", &PatchObjectDeleteMetadata},
      {"patch-object-content-type", &PatchObjectContentType},
      {"make-object-public", &MakeObjectPublic},
      {"read-object-unauthenticated", &ReadObjectUnauthenticated},
      {"generate-encryption-key", &GenerateEncryptionKey},
      {"write-encrypted-object", &WriteEncryptedObject},
      {"read-encrypted-object", &ReadEncryptedObject},
      {"compose-object", &ComposeObject},
      {"compose-object-from-encrypted-objects",
       &ComposeObjectFromEncryptedObjects},
      {"write-object-with-kms-key", &WriteObjectWithKmsKey},
  };
  for (auto&& kv : commands) {
    try {
      int fake_argc = 0;
      kv.second(client, fake_argc, argv);
    } catch (Usage const& u) {
      command_usage += "    ";
      command_usage += u.msg;
      command_usage += "\n";
    }
  }

  if (argc < 2) {
    PrintUsage(argc, argv, "Missing command");
    return 1;
  }

  std::string const command = ConsumeArg(argc, argv);
  auto it = commands.find(command);
  if (commands.end() == it) {
    PrintUsage(argc, argv, "Unknown command: " + command);
    return 1;
  }

  it->second(client, argc, argv);

  return 0;
} catch (Usage const& ex) {
  PrintUsage(argc, argv, ex.msg);
  return 1;
} catch (std::exception const& ex) {
  std::cerr << "Standard C++ exception raised: " << ex.what() << std::endl;
  return 1;
}
