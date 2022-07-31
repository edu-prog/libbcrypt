find_package(Threads REQUIRED)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(${PROJECT_NAME}_tests bcrypt_tests.cpp)

target_include_directories(${PROJECT_NAME}_tests PRIVATE ../include)

target_link_libraries(${PROJECT_NAME}_tests PUBLIC bcrypt gtest_main)

include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME}_tests cache::lru-cache)