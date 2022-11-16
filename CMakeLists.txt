cmake_minimum_required(VERSION 3.23)
project(Otex)

set(CMAKE_CXX_STANDARD 17)

find_package(cryptopp CONFIG REQUIRED)

add_executable(Otex main.cpp)

target_link_libraries(Otex PRIVATE cryptopp::cryptopp)