cmake_minimum_required(VERSION 3.3)
project(DES)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -m64")

set(SOURCE_FILES main.cpp)
add_executable(DES ${SOURCE_FILES})