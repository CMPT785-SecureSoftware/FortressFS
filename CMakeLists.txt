cmake_minimum_required(VERSION 3.10)
project(SecureFS LANGUAGES CXX)

# Use C++17 or later
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required libraries
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Collect source files
file(GLOB SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/app/*.cpp"
)

add_executable(securefs ${SOURCES})

# Just link with -lreadline directly
target_link_libraries(securefs PRIVATE -lreadline)

target_link_libraries(securefs OpenSSL::SSL OpenSSL::Crypto Readline::Readline)