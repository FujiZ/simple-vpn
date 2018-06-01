cmake_minimum_required(VERSION 3.10)
project(simple_vpn C)

set(CMAKE_C_STANDARD 99)

find_package(Threads REQUIRED)

add_executable(simple-vpn vpn.c main.c)

target_link_libraries(simple-vpn Threads::Threads)
