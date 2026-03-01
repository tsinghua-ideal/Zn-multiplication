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

#ifdef DEBUG
static void printCts(const std::vector<Ciphertext<DCRTPoly>> &cts,
                     std::string label) {
  std::cout << label << "[";
  for (auto &ct : cts) {
    Plaintext pt;
    sk->GetCryptoContext()->Decrypt(sk, ct, &pt);
    std::vector<double> slots = pt->GetRealPackedValue();
    std::cout << label << " [";
    for (auto x : slots) {
      if (std::abs(x) < 0.1) {
        std::cout << "0 ";
      } else {
        printf("%.1f ", x);
      }
    }
    std::cout << ']' << std::endl;
  }
}
#endif
/*******************************************************************/
int main(int argc, char *argv[]) {
  if (argc < 2 || !std::isdigit(argv[1][0])) {
    std::cout << "Usage: " << argv[0] << " instance-size [--count_only]\n";
    std::cout << "  Instance-size: 0-TOY, 1-SMALL, 2-MEDIUM, 3-LARGE\n";
    return 0;
  }
  auto size = static_cast<InstanceSize>(std::stoi(argv[1]));

  InstanceParams prms(size);
  auto timing_fname = prms.iodir() / "server_reported_steps.json";
  auto start_server = std::chrono::system_clock::now();

  // Read the crypto context and the public key from disk
  CryptoContext<DCRTPoly> cc;
  if (!Serial::DeserializeFromFile(prms.keydir() / "cc.bin", cc,
                                   SerType::BINARY)) {
    throw std::runtime_error("Failed to get CryptoContext from " +
                             prms.keydir().string());
  }
  PublicKey<DCRTPoly> pk;
  if (!Serial::DeserializeFromFile(prms.keydir() / "pk.bin", pk,
                                   SerType::BINARY)) {
    throw std::runtime_error("Failed to get public key from " +
                             prms.keydir().string());
  }
#ifdef DEBUG // Read also the secret key for debugging
  if (!Serial::DeserializeFromFile(prms.keydir() / "sk.bin", sk,
                                   SerType::BINARY)) {
    throw std::runtime_error("Failed to get secret key from " +
                             prms.keydir().string());
  }
#endif

  std::ifstream emult_file(prms.keydir() / "mk.bin",
                           std::ios::in | std::ios::binary);
  if (!emult_file.is_open() ||
      !cc->DeserializeEvalMultKey(emult_file, SerType::BINARY)) {
    throw std::runtime_error("Failed to get re-linearization key from " +
                             prms.keydir().string());
  }

  std::ifstream erot_file(prms.keydir() / "rk.bin",
                          std::ios::in | std::ios::binary);
  if (!erot_file.is_open() ||
      !cc->DeserializeEvalAutomorphismKey(erot_file, SerType::BINARY)) {
    throw std::runtime_error("Failed to get rotation keys from " +
                             prms.keydir().string());
  }

  // Read lhs and rhs from disk
  auto lhs_name = prms.encdir() / "lhs.bin";
  Ciphertext<DCRTPoly> lhs;
  if (!Serial::DeserializeFromFile(lhs_name, lhs, SerType::BINARY)) {
    throw std::runtime_error("failed to read query ciphertext from " +
                             lhs_name.string());
  }
  auto rhs_name = prms.encdir() / "rhs.bin";
  Ciphertext<DCRTPoly> rhs;
  if (!Serial::DeserializeFromFile(rhs_name, rhs, SerType::BINARY)) {
    throw std::runtime_error("failed to read query ciphertext from " +
                             rhs_name.string());
  }
  log_step(0, "Loading keys");

  auto start_computing = std::chrono::system_clock::now();

  log_step(1, "Performing homomorphic multiplication");

  auto zN = 64;
  ZLinearTransform::Initialize(zN);
  DiscreteFourierTransform::Initialize(zN * 2, zN / 2);

  LeveledZ z = std::make_shared<LeveledZImpl>();
  UserZ u = std::make_shared<UserZImpl>(z);

  auto ctRes = u->EvalMultFullInZ(lhs, rhs);

#ifdef DEBUG
  printCts({result[0]}, " summed match vector:");
#endif
  auto now = std::chrono::system_clock::now();
  int64_t comp_s =
      std::chrono::duration_cast<std::chrono::seconds>(now - start_computing)
          .count();
  int64_t total_s =
      std::chrono::duration_cast<std::chrono::seconds>(now - start_server)
          .count();
  store_server_time(timing_fname, comp_s, total_s);

  std::string out_fname = prms.downloaddir() / "results.bin";
  std::filesystem::create_directories(prms.downloaddir());
  if (!Serial::SerializeToFile(out_fname, ctRes, SerType::BINARY)) {
    throw std::runtime_error("Failed to write ciphertext to " + out_fname);
  }
  return 0;
}
/*******************************************************************/
/*******************************************************************/