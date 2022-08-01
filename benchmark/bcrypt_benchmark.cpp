#include <benchmark/benchmark.h>
#include "bcrypt/BCrypt.hpp"

namespace {
void GenerateHash(benchmark::State& state) {
  for (auto _ : state) {
    auto hash = bcrypt::generate_hash("L35avtaLumUwI64YisGHbGXVOZwmynLF");
    benchmark::DoNotOptimize(hash);
  }
}
BENCHMARK(GenerateHash);

void ValidationHash(benchmark::State& state) {
  for (auto _ : state) {
    constexpr std::array<char, 64> hash = {
        36,  50, 97,  36,  49,  48, 36, 80,  97,  100, 99, 66, 118, 47,  104,
        112, 79, 46,  69,  102, 81, 48, 120, 99,  85,  98, 85, 122, 117, 121,
        81,  66, 81,  52,  76,  72, 67, 83,  122, 101, 81, 90, 108, 102, 113,
        84,  67, 119, 111, 66,  88, 53, 102, 83,  84,  72, 67, 104, 85,  105};

    bool status = bcrypt::compare_hash_and_password(hash, "Password");
    benchmark::DoNotOptimize(status);
  }
}
BENCHMARK(ValidationHash);

}  // namespace

BENCHMARK_MAIN();