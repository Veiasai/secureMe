project(SecureMe)
cmake_minimum_required(VERSION 3.5)

add_definitions(-std=c++11) 
set(CMAKE_BUILD_TYPE "Debug")

add_subdirectory(lib)
add_subdirectory(src)