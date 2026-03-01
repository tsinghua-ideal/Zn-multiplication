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

  // Read the encrypted answer from disk
  Ciphertext<DCRTPoly> eres;
  auto res_file = prms.downloaddir() / "results.bin";
  if (!Serial::DeserializeFromFile(res_file, eres, SerType::BINARY)) {
    throw std::runtime_error("failed to read answer from " + res_file.string());
  }

  // Read the secret keys from disk and decrypt
  Plaintext pt;
  auto sk = read_key(prms);

  auto zN = 64;
  ZLinearTransform::Initialize(zN);
  DiscreteFourierTransform::Initialize(zN * 2, zN / 2);

  LeveledZ z = std::make_shared<LeveledZImpl>();
  UserZ u = std::make_shared<UserZImpl>(z);
  PKEZ pkeZ = std::make_shared<PKEZImpl>(sk);

  auto decResult = pkeZ->Decrypt(eres);
  std::vector<uint64_t> decoded(decResult.size());
  for (size_t i = 0; i < decResult.size(); i++) {
    decoded[i] = decResult[i].ConvertToInt();
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