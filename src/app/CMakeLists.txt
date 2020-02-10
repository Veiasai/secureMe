add_executable(SecureMe main.cpp)

target_link_libraries(SecureMe ${SECCOMP_LIB})
target_include_directories(SecureMe PRIVATE ${SECCOMP_INCLUDE_DIR})