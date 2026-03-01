#ifndef FHEBENCH_UTILS_H_
#define FHEBENCH_UTILS_H_
// utils.h - Utility declerations for fetch-by-similarity
//============================================================================
// Copyright (c) 2025, Amazon Web Services
// All rights reserved.
//
// This software is licensed under the terms of the Apache License v2.
// See the file LICENSE.md for details.
//============================================================================
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

/// Read a binary file into a vector of vectors, all of dimension record_dim
std::vector<uint64_t> read2vec(std::filesystem::path fname) {
  std::ifstream file(fname, std::ios::in);
  if (!file.is_open()) {
    throw std::runtime_error("Cannot open " + fname.string() + " for read");
  }
  std::vector<uint64_t> res;
  // Each line contains a uint64_t
  for (;;) {
    std::string line;
    if (!std::getline(file, line)) {
      break;
    }
    if (line.empty()) {
      continue;
    }
    res.push_back(std::stoull(line));
  }
  return res;
}

void write2disk(std::filesystem::path fname,
                const std::vector<uint64_t> &vecs) {
  std::ofstream file(fname, std::ios::out);
  if (!file.is_open()) {
    throw std::runtime_error("Cannot open " + fname.string() + " for write");
  }
  for (auto &v : vecs) {
    file << v << std::endl;
  }
  file.close();
}

/// Encode the dataset in column order: The input is an n-by-m matrix that
/// we want to transpose, but the rows of the output cannot have dimension
/// above n_slots. To accomodate input matrices with more than n_slots rows,
/// the output is split into ceil(n/n_slots) matrices, each of dimension
/// m-by-n_slots, where the rows of the last one may be padded with zeros.
template <typename T>
std::vector<std::vector<std::vector<double>>>
transpose_matrix(std::vector<std::vector<T>> &mat, size_t n_slots) {
  // ceil( mat.size()/n_slots )
  auto n_ctxt_per_row = (mat.size() + n_slots - 1) / n_slots;
  auto record_dim = mat[0].size();

  //  std::cout << "n_ctxt_per_row=" << n_ctxt_per_row
  //            << ", record_dim=" << record_dim << std::endl;

  // Allocate space
  std::vector<std::vector<std::vector<double>>> transposed(n_ctxt_per_row);
  for (auto &batch : transposed) {
    batch.resize(record_dim);
    for (auto &record : batch) {
      record.assign(n_slots, 0.0);
    }
  }

  // encode in batches of n_slots records at a time
  for (size_t i = 0; i < n_ctxt_per_row; i++) { // go over the batches
    // transpose the next n_slots rows in db
    for (size_t j = 0; j < record_dim; j++) {
      for (size_t k = 0; k < n_slots; k++) {
        auto idx = (i * n_slots) + k;
        if (idx < mat.size()) {
          transposed[i][j][k] = mat[idx][j];
        } else {
          break;
        }
      }
    }
  }
  return transposed; // return the encoded matrix
}

/// Store the accumulated time in a JSON file
inline void store_server_time(std::filesystem::path fname, int64_t compute,
                              int64_t total) {
  std::ofstream file(fname);
  if (file.is_open()) {
    file << "{\n";
    file << "  \"Encrypted computation\": " << compute << ',' << std::endl;
    file << "  \"Total\": " << total << std::endl;
    file << "}\n";
    file.close();
  } else {
    std::cerr << "Unable to open file " << fname << std::endl;
  }
}

#include <chrono>
#include <iomanip>
#include <sstream>
/// Returns the current time in the format H:M:S, and also duration since
/// last call in seconds (or 0 if this is the first call, or reset==true).
inline std::tuple<std::string, int64_t>
getCurrentTimeFormatted(bool reset = false) {
  using namespace std::chrono;
  static std::chrono::system_clock::time_point previous;
  auto now = system_clock::now();
  auto now_c = system_clock::to_time_t(now);

  // Format hours, minutes, seconds
  std::stringstream ss;
  ss << std::put_time(std::localtime(&now_c), "%H:%M:%S");

  // If not the 1st call, also print duration
  int64_t n_seconds = 0;
  if (!reset && previous != system_clock::time_point{}) {
    // Compute the duration between now and previous and report it
    n_seconds = duration_cast<seconds>(now - previous).count();
  }
  previous = now;
  return std::make_pair(ss.str(), n_seconds);
}
#endif // ifdef FHEBENCH_UTILS_H_
