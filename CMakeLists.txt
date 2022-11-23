cmake_minimum_required(VERSION 3.22)
project(Otex)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS -02)
find_package(cryptopp CONFIG REQUIRED)

add_executable(Otex main.cpp elgamal.cpp elgamal.h InitialOT.cpp InitialOT.h)

target_link_libraries(Otex PRIVATE cryptopp::cryptopp)