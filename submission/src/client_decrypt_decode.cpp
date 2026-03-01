// client_decrypt_decode.cpp - decrypting answer from server
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
#include "math/dftransform.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "scheme/ckksrns/z-fhe.h"
#include "scheme/ckksrns/z-pke.h"
#include "scheme/ckksrns/z-user-advanced.h"
#include "scheme/ckksrns/z-user.h"

#include "params.h"
#include "utils.h"

using namespace lbcrypto;

// Read public encryption key from disk
PrivateKey<DCRTPoly> read_key(InstanceParams prms);

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cout << "Usage: " << argv[0] << " instance-size\n";
    std::cout << "  Instance-size: single, small, medium, large\n";
    return 0;
  }
  auto size = static_cast<InstanceSize>(instance_size_from_name(argv[1]));
  InstanceParams prms(size);

  // Read the secret keys from disk and decrypt
  Plaintext pt;
  auto sk = read_key(prms);

  auto vecSize = prms.getVecSize();
  auto zSlots = prms.getZSlots();
  size_t numCts = (vecSize + zSlots - 1) / zSlots;

  if (vecSize == 1) {
    zSlots = 1; // for the single instance, we only have one value, so we can
                // set zSlots to 1 to avoid unnecessary padding
  }

  auto zN = prms.getZN();
  ZLinearTransform::Initialize(zN);
  DiscreteFourierTransform::Initialize(zN * zSlots * 2, zN * zSlots / 2);

  LeveledZ z = std::make_shared<LeveledZImpl>();
  UserZ u = std::make_shared<UserZImpl>(z);
  PKEZ pkeZ = std::make_shared<PKEZImpl>(sk);

  std::vector<uint64_t> decoded(prms.getVecSize());

  for (size_t i = 0; i != numCts; i++) {
    // Read the encrypted answer from disk
    Ciphertext<DCRTPoly> ct;
    auto res_file = prms.downloaddir() /
                    (std::string("result-") + std::to_string(i) + ".bin");
    if (!Serial::DeserializeFromFile(res_file, ct, SerType::BINARY)) {
      throw std::runtime_error("failed to read answer from " +
                               res_file.string());
    }
    auto pt = pkeZ->Decrypt(ct);
    for (size_t j = 0; j < pt.size(); j++) {
      auto idx = i * zSlots + j;
      if (idx < decoded.size()) {
        decoded[idx] = pt[j].ConvertToInt();
      }
    }
  }

  std::filesystem::create_directories(prms.outputdir());
  write2disk(prms.outputdir() / "out.txt", decoded);
  return 0;
}

// Read public encryption key from disk
PrivateKey<DCRTPoly> read_key(InstanceParams prms) {
  CryptoContext<DCRTPoly> cc;
  if (!Serial::DeserializeFromFile(prms.publickeydir() / "cc.bin", cc,
                                   SerType::BINARY)) {
    throw std::runtime_error("Failed to get CryptoContext from " +
                             prms.publickeydir().string());
  }
  PrivateKey<DCRTPoly> sk;
  if (!Serial::DeserializeFromFile(prms.secretkeydir() / "sk.bin", sk,
                                   SerType::BINARY)) {
    throw std::runtime_error("Failed to get secret key from " +
                             prms.secretkeydir().string());
  }
  return sk;
}