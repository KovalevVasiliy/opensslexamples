cmake_minimum_required(VERSION 3.23)
project(untitled2)

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS})

add_executable(untitled2 main.cpp certtools.cpp certtools.h)
target_link_libraries(untitled2 OpenSSL::SSL)