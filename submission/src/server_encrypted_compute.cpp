// server_encrypted_computation.cpp - encrypted fetch-by-similarity
//============================================================================
// Copyright (c) 2025, Amazon Web Services
// All rights reserved.
//
// This software is licensed under the terms of the Apache License v2.
// See the file LICENSE.md for details.
//============================================================================
#include <cassert>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h" // header files needed for (de)serialization
#include "key/key-ser.h"
#include "math/dftransform.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include "scheme/ckksrns/z-fhe.h"
#include "scheme/ckksrns/z-pke.h"
#include "scheme/ckksrns/z-user-advanced.h"
#include "scheme/ckksrns/z-user.h"

#include "params.h"
#include "utils.h"

using namespace lbcrypto;

#undef DEBUG
#ifdef DEBUG
PrivateKey<DCRTPoly> sk;
#endif

// A utility function to get one encrypted ciphertext from the dataset. This
// implementation assumes that ciphertexts are just separate files on disk,
// it should be re-written if they are streamed from a remote location.
inline Ciphertext<DCRTPoly> get_ctxt(fs::path ct_name) {
  Ciphertext<DCRTPoly> ct;
  if (!Serial::DeserializeFromFile(ct_name, ct, SerType::BINARY)) {
    throw std::runtime_error("failed to read ciphertext from " +
                             ct_name.string());
  }
  return ct;
}

// Print logging information to stdout
void log_step(int num, std::string name) {
  auto [timestamp, duration] = getCurrentTimeFormatted();
  std::cout << timestamp << " [server] " << num << ": " << name << " completed";
  if (duration > 0) {
    std::cout << " (elapsed " << duration << "s)";
  }
  std::cout << std::endl;
}

/*******************************************************************/
int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cout << "Usage: " << argv[0] << " instance-size\n";
    std::cout << "  Instance-size: single, small, medium, large\n";
    return 0;
  }
  auto size = static_cast<InstanceSize>(instance_size_from_name(argv[1]));

  InstanceParams prms(size);
  auto timing_fname = prms.iodir() / "server_reported_steps.json";
  auto start_server = std::chrono::system_clock::now();

  // Read the crypto context and the public key from disk
  CryptoContext<DCRTPoly> cc;
  if (!Serial::DeserializeFromFile(prms.publickeydir() / "cc.bin", cc,
                                   SerType::BINARY)) {
    throw std::runtime_error("Failed to get CryptoContext from " +
                             prms.publickeydir().string());
  }
  PublicKey<DCRTPoly> pk;
  if (!Serial::DeserializeFromFile(prms.publickeydir() / "pk.bin", pk,
                                   SerType::BINARY)) {
    throw std::runtime_error("Failed to get public key from " +
                             prms.publickeydir().string());
  }

  std::ifstream emult_file(prms.publickeydir() / "mk.bin",
                           std::ios::in | std::ios::binary);
  if (!emult_file.is_open() ||
      !cc->DeserializeEvalMultKey(emult_file, SerType::BINARY)) {
    throw std::runtime_error("Failed to get re-linearization key from " +
                             prms.publickeydir().string());
  }

  // std::ifstream erot_file(prms.keydir() / "rk.bin",
  //                         std::ios::in | std::ios::binary);
  // if (!erot_file.is_open() ||
  //     !cc->DeserializeEvalAutomorphismKey(erot_file, SerType::BINARY)) {
  //   throw std::runtime_error("Failed to get rotation keys from " +
  //                            prms.keydir().string());
  // }

  auto vecSize = prms.getVecSize();
  auto zSlots = prms.getZSlots();
  size_t numCts = (vecSize + zSlots - 1) / zSlots;

  if (vecSize == 1) {
    zSlots = 1; // for the single instance, we only have one value, so we can
                // set zSlots to 1 to avoid unnecessary padding
  }

  auto zN = prms.getZN();
  ZLinearTransform::Initialize(zN);
  // Server: for MultFull, we also need to initialize for (zN * 2, zN / 2)
  DiscreteFourierTransform::Initialize(zN * 2, zN / 2);
  DiscreteFourierTransform::Initialize(zN * zSlots * 2, zN * zSlots / 2);

  LeveledZ z = std::make_shared<LeveledZImpl>();
  UserZ u = std::make_shared<UserZImpl>(z);

  log_step(0, "Loading keys");

  std::vector<Ciphertext<DCRTPoly>> lhsCts(numCts), rhsCts(numCts);
#pragma omp parallel for num_threads(                                          \
        OpenFHEParallelControls.GetThreadLimit(numCts))
  for (size_t i = 0; i < numCts; i++) {
    auto lhs_name =
        prms.uploaddir() / (std::string("lhs-") + std::to_string(i) + ".bin");

    // Read lhs and rhs from disk
    Ciphertext<DCRTPoly> lhs;
    if (!Serial::DeserializeFromFile(lhs_name, lhs, SerType::BINARY)) {
      throw std::runtime_error("failed to read query ciphertext from " +
                               lhs_name.string());
    }
    auto rhs_name =
        prms.uploaddir() / (std::string("rhs-") + std::to_string(i) + ".bin");
    Ciphertext<DCRTPoly> rhs;
    if (!Serial::DeserializeFromFile(rhs_name, rhs, SerType::BINARY)) {
      throw std::runtime_error("failed to read query ciphertext from " +
                               rhs_name.string());
    }
    lhsCts[i] = lhs;
    rhsCts[i] = rhs;
  }

  log_step(1, "Loading input ciphertexts");

  auto start_computing = std::chrono::system_clock::now();

  std::vector<Ciphertext<DCRTPoly>> result(numCts);
  for (size_t i = 0; i < numCts; i++) {
    auto lhs = lhsCts[i];
    auto rhs = rhsCts[i];
    auto ctRes = u->EvalMultFullInZ(lhs, rhs);
    result[i] = ctRes;
  }

  log_step(2, "Performing homomorphic multiplication");

  auto now = std::chrono::system_clock::now();
  int64_t comp_s =
      std::chrono::duration_cast<std::chrono::seconds>(now - start_computing)
          .count();
  int64_t total_s =
      std::chrono::duration_cast<std::chrono::seconds>(now - start_server)
          .count();
  store_server_time(timing_fname, comp_s, total_s);

  std::filesystem::create_directories(prms.downloaddir());

#pragma omp parallel for num_threads(                                          \
        OpenFHEParallelControls.GetThreadLimit(numCts))
  for (size_t i = 0; i < numCts; i++) {
    auto ctRes = result[i];
    std::string out_fname = prms.downloaddir() / (std::string("result-") +
                                                  std::to_string(i) + ".bin");
    if (!Serial::SerializeToFile(out_fname, ctRes, SerType::BINARY)) {
      throw std::runtime_error("Failed to write ciphertext to " + out_fname);
    }
  }

  log_step(3, "Writing results to disk");

  return 0;
}
/*******************************************************************/
/*******************************************************************/