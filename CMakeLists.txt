cmake_minimum_required(VERSION 3.10)

# Project name and version
project(fhash VERSION 1.0 LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find OpenSSL library
find_package(OpenSSL REQUIRED)

# Add the executable
add_executable(fhash sha.cpp md.cpp main.cpp)

# Link OpenSSL libraries
target_link_libraries(fhash OpenSSL::SSL OpenSSL::Crypto)
