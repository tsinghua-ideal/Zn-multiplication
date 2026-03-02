#ifndef PARAMS_H_
#define PARAMS_H_
/// params.h - parameters and directory structure for similarity search
//============================================================================
// Copyright (c) 2025, Amazon Web Services
// All rights reserved.
//
// This software is licensed under the terms of the Apache License v2.
// See the file LICENSE.md for details.
//============================================================================
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>
namespace fs = std::filesystem;

// an enum for benchmark size
enum InstanceSize { SINGLE = 0, SMALL = 1, MEDIUM = 2, LARGE = 3 };
inline std::string instance_name(const InstanceSize size) {
  if (unsigned(size) > unsigned(InstanceSize::LARGE)) {
    return "unknown";
  }
  static const std::string names[] = {"single", "small", "medium", "large"};
  return names[int(size)];
}
inline InstanceSize instance_size_from_name(const std::string &name) {
  for (int i = 0; i <= int(InstanceSize::LARGE); i++) {
    if (name == instance_name(static_cast<InstanceSize>(i))) {
      return static_cast<InstanceSize>(i);
    }
  }
  throw std::invalid_argument("Invalid instance name: " + name);
}

// Parameters that differ for different instance sizes
class InstanceParams {
  const InstanceSize size;
  int vecSize;      // dimension of the uint64_t vector
  int ringDim;      // dimenion of the FHE ring
  fs::path rootdir; // root of the submission dir structure (see below)

public:
  // Constructor
  explicit InstanceParams(InstanceSize _size,
                          fs::path _rootdir = fs::current_path())
      : size(_size), rootdir(_rootdir) {
    if (unsigned(_size) > unsigned(InstanceSize::LARGE)) {
      throw std::invalid_argument("Invalid instance size");
    }
    // parameters for sizes:       single  small   medium      large
    static const int vecSizes[] = {1, 1000, 100000, 10000000};

    // Manual Ring Dim selection
    ringDim = 1 << 13;
    vecSize = vecSizes[int(_size)];
  }

  // Getters for all the parameters. There are no setters, once
  // an object is constrcuted these parameters cannot be modified.
  const InstanceSize getSize() const { return size; }
  int getRingDim() const { return ringDim; }
  int getZN() const { return 64; }
  int getZSlots() const { return ringDim / getZN(); }
  int getVecSize() const { return vecSize; }

  // Directory structure: each submission to the fetch-by-similarity
  // workload in the FHE benchmarking is a branch of the repository
  //      https://github.com/fhe-benchmarking/fetch-by-similarity,
  // with (a subset of) the following directory structure:
  // [root] /
  //  ├─datasets/   # Holds cleartext data (centers.bin, db.bin, query.bin)
  //    ├─ toy/     # each instance-size in in a separate subdirectory
  //    ├─ small/
  //    ├─ medium/
  //    ├─ large/
  //  ├─docs/       # Documentation (beyond the top-level README.md)
  //  ├─harness/    # Scripts to generate data, run workload, check results
  //  ├─build/      # Handle installing dependencies and building the project
  //  ├─submission/ # The implementation, this is what the submitters modify
  //    └─ README.md  # likely also a src/ subdirectory, CMakeLists.txt, etc.
  //  ├─io/         # Directory to hold the I/O between client & server parts
  //    ├─ toy/       # The reference implementation has subdirectories
  //       ├─ keys/       # holds the keys
  //       └─ encrypted/  # holds the ciphertexts (split into subdirectories)
  //    ├─ small/
  //       …
  //    ├─ medium/
  //       …
  //    ├─ large/
  //       …
  // The relevant directories where things are found
  fs::path rtdir() const { return rootdir; }
  fs::path iodir() const { return rootdir / "io" / instance_name(size); }
  fs::path secretkeydir() const { return iodir() / "secret_keys"; }
  fs::path publickeydir() const { return iodir() / "public_keys"; }
  fs::path uploaddir() const { return iodir() / "ciphertexts_upload"; }
  fs::path downloaddir() const { return iodir() / "ciphertexts_download"; }
  fs::path outputdir() const { return iodir() / "cleartext_output"; }
  fs::path datadir() const {
    return rootdir / "datasets" / instance_name(size);
  }
};

#endif // ifndef PARAMS_H_