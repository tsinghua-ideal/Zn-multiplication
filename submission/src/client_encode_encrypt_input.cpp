// client_encode_encrypt_db.cpp - encrypting the dataset
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

#include "math/dftransform.h"
#include "scheme/ckksrns/z-fhe.h"
#include "scheme/ckksrns/z-pke.h"
#include "scheme/ckksrns/z-user-advanced.h"
#include "scheme/ckksrns/z-user.h"

#include "params.h"
#include "utils.h"

using namespace lbcrypto;

// Read public encryption key from disk
PublicKey<DCRTPoly> read_keys(InstanceParams prms);
void add_markers(std::vector<std::vector<int16_t>> &payloads);

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cout << "Usage: " << argv[0] << " instance-size\n";
    std::cout << "  Instance-size: single, small, medium, large\n";
    return 0;
  }
  auto size = static_cast<InstanceSize>(instance_size_from_name(argv[1]));
  InstanceParams prms(size);

  // Read from datasets/<instance-size>/lhs.txt
  auto lhs = read2vec(prms.datadir().append("lhs.txt"));
  auto rhs = read2vec(prms.datadir().append("rhs.txt"));

  if (lhs.size() != rhs.size()) {
    throw std::runtime_error("Mismatched number of records in lhs and rhs");
  }

  if (lhs.size() != static_cast<size_t>(prms.getVecSize())) {
    throw std::runtime_error(
        "Mismatched number of records in lhs and instance params");
  }

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
  const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
      cc->GetCryptoParameters());
  auto elemParam = cc->GetCryptoParameters()->GetElementParams();
  auto sfq0 = cryptoParams->GetScalingFactorBFP(0);

  auto vecSize = prms.getVecSize();
  auto zSlots = prms.getZSlots();
  size_t numCts = (vecSize + zSlots - 1) / zSlots;

  if (vecSize == 1) {
    zSlots = 1; // for the single instance, we only have one value, so we can
                // set zSlots to 1 to avoid unnecessary padding
  }

  std::cout << std::get<0>(getCurrentTimeFormatted())
            << " [client] Number of ciphertexts to generate for lhs (or rhs): "
            << numCts << std::endl;

  auto zN = prms.getZN();
  ZLinearTransform::Initialize(zN);
  // Server: for MultFull, we also need to initialize for (zN * 2, zN / 2)
  DiscreteFourierTransform::Initialize(zN * zSlots * 2, zN * zSlots / 2);

  LeveledZ z = std::make_shared<LeveledZImpl>();
  UserZ u = std::make_shared<UserZImpl>(z);
  PKEZ pkeZ = std::make_shared<PKEZImpl>(pk);

#pragma omp parallel for num_threads(                                          \
        OpenFHEParallelControls.GetThreadLimit(numCts))
  for (size_t i = 0; i < numCts; i++) {
    std::vector<uint64_t> lhsInner(zSlots), rhsInner(zSlots);

    auto startIdx = i * zSlots;
    auto endIdx = std::min(startIdx + zSlots, static_cast<size_t>(vecSize));

    for (size_t j = startIdx; j < endIdx; j++) {
      lhsInner[j - startIdx] = lhs[j];
      rhsInner[j - startIdx] = rhs[j];
    }

    auto ptxt1 =
        ZEncodingImpl::encodeArith(lhsInner, zN, zSlots, elemParam, sfq0);
    auto ptxt2 =
        ZEncodingImpl::encodeArith(rhsInner, zN, zSlots, elemParam, sfq0);

    auto ctLHS = pkeZ->Encrypt(ptxt1);
    auto ctRHS = pkeZ->Encrypt(ptxt2);

    auto dir = prms.uploaddir();
    std::filesystem::create_directories(dir);

    auto lhs_ct_fname =
        dir / (std::string("lhs-") + std::to_string(i) + ".bin");
    if (!Serial::SerializeToFile(lhs_ct_fname, ctLHS, SerType::BINARY)) {
      throw std::runtime_error("failed to write file " + lhs_ct_fname.string());
    }
    auto rhs_ct_fname =
        dir / (std::string("rhs-") + std::to_string(i) + ".bin");
    if (!Serial::SerializeToFile(rhs_ct_fname, ctRHS, SerType::BINARY)) {
      throw std::runtime_error("failed to write file " + rhs_ct_fname.string());
    }
  }
  return 0;
}