// client_key_generation.cpp - Client key generation
//============================================================================
// Copyright (c) 2025, Amazon Web Services
// All rights reserved.
//
// This software is licensed under the terms of the Apache License v2.
// See the file LICENSE.md for details.
//============================================================================
#include <cassert>

#include "openfhe.h"
// header files needed for de/serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include "params.h"
#include "utils.h"

using namespace lbcrypto;

KeyPair<DCRTPoly> key_gen(const InstanceParams &prms);

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cout << "Usage: " << argv[0] << " instance-size\n";
    std::cout << "  Instance-size: single, small, medium, large\n";
    return 0;
  }
  auto size = static_cast<InstanceSize>(instance_size_from_name(argv[1]));
  InstanceParams prms(size);

  // Generate fresh keys
  auto keys = key_gen(prms);
  auto cc = keys.publicKey->GetCryptoContext();

  // Store context and keys to disk
  std::filesystem::create_directory(prms.secretkeydir(), prms.rtdir());
  std::filesystem::create_directory(prms.publickeydir(), prms.rtdir());
  if (!Serial::SerializeToFile(prms.publickeydir() / "cc.bin", cc,
                               SerType::BINARY) ||
      !Serial::SerializeToFile(prms.publickeydir() / "pk.bin", keys.publicKey,
                               SerType::BINARY) ||
      !Serial::SerializeToFile(prms.secretkeydir() / "sk.bin", keys.secretKey,
                               SerType::BINARY)) {
    throw std::runtime_error("Failed to write keys to " +
                             prms.publickeydir().string());
  }
  std::ofstream emult_file(prms.publickeydir() / "mk.bin",
                           std::ios::out | std::ios::binary);
  // std::ofstream erot_file(prms.publickeydir() / "rk.bin",
  //                         std::ios::out | std::ios::binary);
  if (!emult_file.is_open() ||
      // !erot_file.is_open() ||
      !cc->SerializeEvalMultKey(emult_file, SerType::BINARY)) {
    //! cc->SerializeEvalAutomorphismKey(erot_file, SerType::BINARY)) {
    throw std::runtime_error("Failed to write eval keys to " +
                             prms.publickeydir().string());
  }
  return 0;
}

// Generate keys that include all the rotations needed for replication,
// running sums, and total sums
KeyPair<DCRTPoly> key_gen(const InstanceParams &prms) {
  CCParams<CryptoContextCKKSRNS> cParams;
  cParams.SetSecretKeyDist(UNIFORM_TERNARY);
  cParams.SetKeySwitchTechnique(HYBRID);
  // Two level for Mult, 1 level for extra spaces for overflow.
  cParams.SetMultiplicativeDepth(3);
  cParams.SetRingDim(prms.getRingDim());
  cParams.SetSecurityLevel(HEStd_128_classic);
  cParams.SetScalingTechnique(FLEXIBLEMANUAL);
  cParams.SetScalingModSize(43);
  cParams.SetFirstModSize(43);
  AUXMODSIZE_FLEXIBLEMANUAL = 50;
  CryptoContext<DCRTPoly> cc = GenCryptoContext(cParams);

  // Enable features that you wish to use
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  assert(unsigned(prms.getRingDim()) == cc->GetRingDimension());

  auto keyPair = cc->KeyGen();           // secret/public keys
  cc->EvalMultKeyGen(keyPair.secretKey); // re-linearization key
  return keyPair;
}
