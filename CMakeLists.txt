cmake_minimum_required(VERSION 3.2.2)
project(DHCP_CLIENT CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
message(STATUS "GCC: Enabled c++17 support")

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/bin)

add_subdirectory(src)