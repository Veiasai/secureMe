aux_source_directory(. DIR_SRCS)

add_executable(secureme ${DIR_SRCS})

target_link_libraries(secureme ${SECCOMP_LIB})
target_link_libraries(secureme cxxopts)
target_link_libraries(secureme spdlog)
target_link_libraries(secureme yaml-cpp)

target_include_directories(secureme PRIVATE ${SECCOMP_INCLUDE_DIR})