#pragma once

#include <array>
#include <bitset>
#include <cstdint>
#include <stdexcept>
#include <string>

#include "bcrypt.h"

namespace bcrypt {

enum class Cost : std::uint8_t {
  kMinCost = 4,
  kDefaultCost = 12,
  kMaxCost = 31
};

inline constexpr auto kBcryptHashSize = BCRYPT_HASHSIZE;

using array_hash_t = std::array<char, kBcryptHashSize>;

array_hash_t generate_hash(std::string_view password,
                           Cost cost = Cost::kDefaultCost) {
  array_hash_t hash;
  array_hash_t salt;

  int errorCode = 0;

  errorCode = bcrypt_gensalt(static_cast<int>(cost), salt.data());
  if (errno) {
    throw std::runtime_error("bcrypt: can not generate salt");
  }

  errorCode = bcrypt_hashpw(password.data(), salt.data(), hash.data());
  if (errno) {
    throw std::runtime_error("bcrypt: can not generate hash");
  }

  return hash;
}

bool compare_hash_and_password(array_hash_t hash, std::string_view password) {
  return bcrypt_checkpw(password.data(), hash.data()) == 0;
}
}  // namespace bcrypt