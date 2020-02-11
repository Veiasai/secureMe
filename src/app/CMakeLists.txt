add_executable(secureme main.cpp)

target_link_libraries(secureme ${SECCOMP_LIB})
target_include_directories(secureme PRIVATE ${SECCOMP_INCLUDE_DIR})