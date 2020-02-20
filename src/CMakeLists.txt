aux_source_directory(app APP_DIR)
aux_source_directory(test TEST_DIR)

add_executable(secureme ${APP_DIR})
add_executable(smtest ${TEST_DIR})

target_link_libraries(secureme ${SECCOMP_LIB})
target_link_libraries(secureme cxxopts)
target_link_libraries(secureme spdlog)
target_link_libraries(secureme yaml-cpp)

target_link_libraries(smtest ${SECCOMP_LIB})
target_link_libraries(smtest cxxopts)
target_link_libraries(smtest spdlog)
target_link_libraries(smtest yaml-cpp)
target_link_libraries(smtest gtest)
target_link_libraries(smtest gmock)

target_include_directories(secureme PRIVATE ${SECCOMP_INCLUDE_DIR})
target_include_directories(smtest PRIVATE ${SECCOMP_INCLUDE_DIR})