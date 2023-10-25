//
//
// Copyright 2023 gRPC authors.
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

#include <grpc/support/port_platform.h>

#if defined(GPR_WINDOWS)

// TODO(gtcooke94) How to best test this?
#include <windows.h>

#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

#include <grpc/support/log.h>

namespace {
std::string GetAbsoluteFilePath(absl::string_view valid_file_dir,
                                absl::string_view file_entry_name) {
  return absl::StrFormat("%s\\t%s", valid_file_dir, file_entry_name);
}
}  // namespace

// Reference for reading directory in Windows:
// https://stackoverflow.com/questions/612097/how-can-i-get-the-list-of-files-in-a-directory-using-c-or-c
// https://learn.microsoft.com/en-us/windows/win32/fileio/listing-the-files-in-a-directory
absl::StatusOr<std::vector<std::string>> GetFilesInDirectory(
    const std::string& crl_directory_path) {
  std::string search_path = crl_directory_path + "/*.*";
  std::vector<std::string> crl_files;
  windows::WIN32_FIND_DATA find_data;
  HANDLE hFind = ::FindFirstFile(search_path.c_str(), &find_data);
  if (hFind != windows::INVALID_HANDLE_VALUE) {
    do {
      if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        std::string file_path;
        GetAbsoluteFilePath(crl_directory_path.c_str(), find_data.cFileName,
                            file_path);
        crl_files.push_back(file_path);
      }
    } while (::FindNextFile(hFind, &find_data));
    ::FindClose(hFind);
    return crl_files;
  } else {
    return absl::InternalError("Could not read crl directory.");
  }
}

#endif  // GPR_WINDOWS