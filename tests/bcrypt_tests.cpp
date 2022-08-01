#include <gtest/gtest.h>
#include <bcrypt/BCrypt.hpp>

TEST(bcrypt, Basic) {
  auto password = "Password";
  auto hash = bcrypt::generate_hash(password);

  EXPECT_TRUE(bcrypt::compare_hash_and_password(hash, password));
}