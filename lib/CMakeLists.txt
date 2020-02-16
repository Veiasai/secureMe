include(ExternalProject)

set(LIBSECCOMP_ROOT          ${CMAKE_BINARY_DIR}/lib/libseccomp-2.4.2)
set(LIBSECCOMP_LIB_DIR       ${LIBSECCOMP_ROOT}/lib)
set(LIBSECCOMP_INCLUDE_DIR   ${LIBSECCOMP_ROOT}/include)

set(LIBSECCOMP_URL           https://github.com/seccomp/libseccomp/releases/download/v2.4.2/libseccomp-2.4.2.tar.gz)
set(LIBSECCOMP_CONFIGURE     cd ${LIBSECCOMP_ROOT}/src/libseccomp && ./configure --prefix=${LIBSECCOMP_ROOT})
set(LIBSECCOMP_MAKE          cd ${LIBSECCOMP_ROOT}/src/libseccomp && make)
set(LIBSECCOMP_INSTALL       cd ${LIBSECCOMP_ROOT}/src/libseccomp && make install)

ExternalProject_Add(libseccomp
        URL                   ${LIBSECCOMP_URL}
        DOWNLOAD_NAME         libseccomp-2.4.2.tar.gz
        PREFIX                ${LIBSECCOMP_ROOT}
        CONFIGURE_COMMAND     ${LIBSECCOMP_CONFIGURE}
        BUILD_COMMAND         ${LIBSECCOMP_MAKE}
        INSTALL_COMMAND       ${LIBSECCOMP_INSTALL}
)

set(SECCOMP_LIB ${LIBSECCOMP_ROOT}/lib/libseccomp.so PARENT_SCOPE)
set(SECCOMP_INCLUDE_DIR ${LIBSECCOMP_ROOT}/include PARENT_SCOPE)

add_subdirectory(cxxopts)
add_subdirectory(spdlog)
add_subdirectory(yaml-cpp)
add_subdirectory(googletest)