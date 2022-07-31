#include <gtest/gtest.h>
#include <bcrypt/BCrypt.hpp>

TEST(bcrypt, Basic) {
  auto password = "Password";
  auto hash = BCrypt::generateHash(password);

  EXPECT_TRUE(BCrypt::validatePassword(password, hash));
}