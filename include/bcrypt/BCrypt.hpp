#pragma once

#include <array>
#include <bitset>
#include <stdexcept>
#include <string>

#include "bcrypt.h"

inline constexpr auto kBcryptHashSize = BCRYPT_HASHSIZE;

namespace bcrypt {
std::array<char, kBcryptHashSize> generate_hash(std::string_view password,
                                                uint8_t cost = 12) {
  std::array<char, kBcryptHashSize> hash;
  std::array<char, kBcryptHashSize> salt;

  int16_t errorCode = 0;

  errorCode = bcrypt_gensalt(cost, salt.data());
  if (errno) {
    throw std::runtime_error("bcrypt: can not generate salt");
  }

  errorCode = bcrypt_hashpw(password.data(), salt.data(), hash.data());

  if (errno) {
    throw std::runtime_error("bcrypt: can not generate hash");
  }

  return hash;
}

bool compare_hash_and_password(std::array<char, kBcryptHashSize> hash,
                               std::string_view password) {
  return bcrypt_checkpw(password.data(), hash.data()) == 0;
}
}  // namespace bcrypt

// class BCrypt {
//  public:
//   static std::string generateHash(const std::string& password,
//                                   int workload = 12) {
//     char salt[BCRYPT_HASHSIZE];
//     char hash[BCRYPT_HASHSIZE];
//     int ret = bcrypt_gensalt(workload, salt);
//     if (ret != 0) {
//       throw std::runtime_error{"bcrypt: can not generate salt"};
//     }
//     ret = bcrypt_hashpw(password.c_str(), salt, hash);
//     if (ret != 0) throw std::runtime_error{"bcrypt: can not generate hash"};
//     return std::string{hash};
//   }

//   static bool validatePassword(const std::string& password,
//                                const std::string& hash) {
//     return (bcrypt_checkpw(password.c_str(), hash.c_str()) == 0);
//   }
// };
