#include <benchmark/benchmark.h>
#include <bcrypt/BCrypt.hpp>

namespace {
void GenerateHash(benchmark::State& state) {
  for (auto _ : state) {
    auto hash = BCrypt::generateHash("password");
    benchmark::DoNotOptimize(hash);
  }
}
BENCHMARK(GenerateHash);

void ValidationHash(benchmark::State& state) {
  for (auto _ : state) {
    std::string hash =
        "$2a$12$TMeNQeGAG.zbVCQXpbuWrOHR7c7SQZV3qzJPouB8weLmo1XnaKTja";

    bool status = BCrypt::validatePassword("Password", hash);
    benchmark::DoNotOptimize(status);
  }
}
BENCHMARK(ValidationHash);

}  // namespace

BENCHMARK_MAIN();