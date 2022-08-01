#include <benchmark/benchmark.h>
#include "bcrypt/BCrypt.hpp"

namespace {
void GenerateHash(benchmark::State& state) {
  using namespace bcrypt;

  for (auto _ : state) {
    constexpr auto kSize = 10;

    std::array<array_hash_t, kSize> hashes;
    std::array<std::string_view, kSize> passwords = {
        "xBex5KMaPks9QF8C7oL0KA3YiJ35JyFxjJDXIMa6kfwvhd3wggGd5FNCfykxx7ruw",
        "uCnaZADVsy3mRoDcsrAmAcPGg5qkQDdGx4PyeALwJLcLCKh6OK4ZdFDwTuHPdRQ7d",
        "U7rdCJ8G5hxscK54heQJCSCWDVEtmNyfNPuMtCngthMI5qzZSBBR2l1eN3IvPQ5DW",
        "wOHgRAjSP4Xxmh2Ds8i3kEZn7Pm55kGjQ9DNglu6eDOMEoaAbe74YpvVF6Jub3A4W",
        "kzRf4i9CyAQaqjS3r99GUxqRwALdLsXAX7nGXBW2Dz7etAgT7vpDEOTKoSfybSBuq",
        "cCkCrWHfZPXSM2koV8t9mylOs0eQx16HyZHiiKSMTdfsn9EFegufncgMJOAIt4Bwf",
        "3lkf5aGYXgFAzBJNTDdTrepRNxNJZmdJnzu0VrTyMZWlfmehZOrYlHMLvyV9EXsqU",
        "eAHoStwkKILvmw4beVu0rs3R3JZaqbAZvY78A2sEWsp2QibhvA0gjGQHjhv7wfda3",
        "rtR0itsSLaiyquiTT2I9AEOunBwmBqZp9njyNsuHza7GyDTr9nxSbxD9cXXEPwikx",
        "n0KvkljHn5OrUuR15N44cmRHiDKjaIQhpucqAJ6xAJOJsLM0vtYkjFSbVJGZYhVtf",
    };

    for (int i = 0; i < kSize; i++) {
      hashes[i] = generate_hash(passwords[i]);
    }

    benchmark::DoNotOptimize(hashes);
  }
}
BENCHMARK(GenerateHash);

void ValidationHash(benchmark::State& state) {
  for (auto _ : state) {
    constexpr auto kSize = 10;

    std::vector<array_hash_t> hashes{
        {36, 50,  97,  36, 49,  48,  36,  66,  111, 102, 71,  113, 70,  87, 116,
         56, 46,  117, 79, 86,  122, 112, 47,  101, 121, 51,  107, 66,  46, 46,
         97, 122, 75,  97, 117, 51,  115, 115, 104, 49,  101, 116, 103, 78, 113,
         97, 52,  117, 65, 105, 68,  112, 51,  99,  83,  52,  56,  78,  79, 87},
        {36,  50,  97,  36,  49,  48,  36,  57,  55, 112, 101, 114,
         69,  70,  79,  121, 84,  85,  110, 112, 57, 70,  89,  98,
         120, 55,  65,  114, 117, 118, 77,  109, 70, 103, 79,  81,
         83,  47,  109, 57,  79,  57,  117, 112, 51, 114, 111, 72,
         85,  118, 114, 113, 89,  73,  53,  65,  57, 47,  77,  67},
        {36,  50,  97, 36,  49,  48,  36,  66,  99, 54,  77, 85,  84,  76,  55,
         110, 112, 67, 116, 121, 48,  98,  106, 54, 88,  87, 117, 115, 117, 72,
         83,  114, 57, 79,  119, 57,  66,  105, 48, 116, 54, 107, 109, 117, 53,
         103, 67,  85, 108, 48,  105, 117, 122, 73, 111, 56, 52,  48,  118, 50},
        {36, 50, 97,  36, 49,  48,  36, 81,  108, 90,  54, 107, 67,  83,  122,
         54, 73, 111, 48, 104, 107, 85, 71,  57,  109, 69, 118, 103, 101, 107,
         98, 99, 100, 66, 55,  67,  73, 107, 101, 90,  52, 74,  109, 66,  66,
         53, 77, 120, 67, 89,  70,  86, 87,  67,  55,  75, 47,  54,  113, 113},
        {36,  50,  97, 36, 49,  48,  36,  70,  84,  46,  105, 82,
         100, 65,  71, 98, 103, 113, 102, 73,  108, 110, 76,  97,
         108, 66,  79, 49, 117, 47,  115, 84,  88,  48,  121, 109,
         78,  112, 76, 82, 90,  52,  108, 113, 112, 68,  49,  49,
         78,  49,  80, 72, 75,  83,  118, 81,  86,  88,  98,  87},
        {36,  50, 97, 36,  49,  48,  36,  46,  75,  54,  104, 116,
         47,  68, 65, 57,  53,  120, 101, 65,  104, 109, 55,  115,
         76,  97, 86, 104, 79,  105, 116, 53,  115, 82,  56,  99,
         99,  74, 82, 83,  48,  69,  106, 103, 117, 104, 70,  80,
         110, 80, 66, 68,  112, 71,  105, 110, 99,  74,  80,  46},
        {36,  50, 97,  36,  49,  48,  36,  102, 54,  78,  116, 48,
         122, 84, 83,  113, 74,  46,  104, 119, 75,  80,  76,  83,
         79,  82, 48,  106, 46,  85,  66,  100, 99,  112, 81,  52,
         56,  73, 86,  51,  52,  97,  106, 106, 76,  71,  53,  85,
         85,  52, 112, 97,  113, 111, 51,  68,  107, 82,  82,  117},
        {36,  50,  97,  36,  49,  48,  36,  65,  101, 117, 73,  70,
         115, 106, 99,  65,  119, 106, 102, 102, 90,  117, 73,  102,
         72,  101, 75,  113, 101, 85,  76,  100, 99,  65,  105, 89,
         56,  114, 109, 119, 72,  116, 103, 76,  118, 120, 54,  46,
         49,  118, 102, 74,  112, 77,  118, 81,  81,  51,  87,  75},
        {36,  50, 97, 36,  49, 48, 36, 68,  90, 104, 97,  71,  55,  119, 52,
         110, 47, 70, 53,  70, 73, 65, 86,  47, 73,  70,  77,  90,  79,  86,
         110, 55, 66, 115, 66, 81, 79, 76,  51, 76,  79,  48,  116, 65,  66,
         97,  87, 65, 106, 67, 76, 52, 108, 81, 103, 105, 120, 67,  101, 83},
        {36,  50,  97,  36,  49,  48, 36,  50,  68,  65,  68,  109,
         66,  116, 57,  102, 82,  69, 122, 97,  105, 120, 118, 56,
         89,  111, 102, 104, 117, 73, 101, 106, 107, 76,  107, 74,
         100, 49,  82,  90,  86,  98, 115, 75,  68,  119, 77,  99,
         122, 105, 119, 102, 65,  66, 108, 86,  104, 73,  78,  117},
    };

    std::array<std::string, kSize> passwords = {
        "xBex5KMaPks9QF8C7oL0KA3YiJ35JyFxjJDXIMa6kfwvhd3wggGd5FNCfykxx7ruw",
        "uCnaZADVsy3mRoDcsrAmAcPGg5qkQDdGx4PyeALwJLcLCKh6OK4ZdFDwTuHPdRQ7d",
        "U7rdCJ8G5hxscK54heQJCSCWDVEtmNyfNPuMtCngthMI5qzZSBBR2l1eN3IvPQ5DW",
        "wOHgRAjSP4Xxmh2Ds8i3kEZn7Pm55kGjQ9DNglu6eDOMEoaAbe74YpvVF6Jub3A4W",
        "kzRf4i9CyAQaqjS3r99GUxqRwALdLsXAX7nGXBW2Dz7etAgT7vpDEOTKoSfybSBuq",
        "cCkCrWHfZPXSM2koV8t9mylOs0eQx16HyZHiiKSMTdfsn9EFegufncgMJOAIt4Bwf",
        "3lkf5aGYXgFAzBJNTDdTrepRNxNJZmdJnzu0VrTyMZWlfmehZOrYlHMLvyV9EXsqU",
        "eAHoStwkKILvmw4beVu0rs3R3JZaqbAZvY78A2sEWsp2QibhvA0gjGQHjhv7wfda3",
        "rtR0itsSLaiyquiTT2I9AEOunBwmBqZp9njyNsuHza7GyDTr9nxSbxD9cXXEPwikx",
        "n0KvkljHn5OrUuR15N44cmRHiDKjaIQhpucqAJ6xAJOJsLM0vtYkjFSbVJGZYhVtf",
    };

    std::array<bool, 10> statuses;

    for (auto i = 0; i < kSize; i++) {
      statuses[i] = compare_hash_and_password(hashes[i], passwords[i]);
    }

    benchmark::DoNotOptimize(statuses);
  }
}
BENCHMARK(ValidationHash);

}  // namespace

BENCHMARK_MAIN();