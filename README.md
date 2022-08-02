# libbcrypt

A c++ wrapper around bcrypt password hashing

## How to build this

This is a CMake based project:

```bash
git clone git@bb.eduprog-team.ru:eduprog/libbcrypt.git
cd libbcrypt
mkdir build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
sudo cmake --build build -j$(nproc) --target install
```

## How to use this

CMakeLists.txt:

```cmake
target_link_library(${PROJECT_NAME} PRIVATE bcrypt)
```

C++:

```cpp
#include <bcrypt/bcrypt.hpp>
#include <iostream>

int main() {
	auto password = "test";
	auto hash = bcrypt::generate_hash(password);

	std::cout << bcrypt::compare_hash_and_password(hash, password) << '\n';
	std::cout << bcrypt::compare_hash_and_password(hash, "test1") << '\n';

	return 0;
}
```
