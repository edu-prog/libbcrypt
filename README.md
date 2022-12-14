# libbcrypt

[![CI](https://github.com/edu-prog/libbcrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/edu-prog/libbcrypt/actions/workflows/ci.yml)

A c++ wrapper around bcrypt password hashing

## How to build this

This is a CMake based project:

```bash
git clone https://github.com/edu-prog/libbcrypt.git
cd libbcrypt
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

## License
Distributed under the [MIT License](LICENSE).
