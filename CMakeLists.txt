project(n2n)
cmake_minimum_required(VERSION 2.6)
include(CheckFunctionExists)
SET(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# N2n release information
execute_process(
    COMMAND scripts/version.sh
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    OUTPUT_VARIABLE PACKAGE_VERSION
    RESULT_VARIABLE GIT_ERROR_CODE
)
if (NOT GIT_ERROR_CODE EQUAL 0)
    # - if we can run version.sh and it exits with an error that is signaling
    #   a build failure.
    # - if we are on windows with no MSYS or Cygwin, we cannot run version.sh
    #   which is the fallback case handled below
    # TODO: Distinguish between these two cases

    # Fallback to just using the non dynamic short version string
    file(STRINGS VERSION PACKAGE_VERSION)
endif (NOT GIT_ERROR_CODE EQUAL 0)

string(STRIP "${PACKAGE_VERSION}" PACKAGE_VERSION)
MESSAGE(STATUS "Build for version: ${PACKAGE_VERSION}")

add_definitions(-DCMAKE_BUILD)
add_definitions(-DPACKAGE_OSNAME="${CMAKE_SYSTEM_NAME}")
add_definitions(-DPACKAGE_VERSION="${PACKAGE_VERSION}")

# third-party directory
set(THIRD_PARTY_DIR ${CMAKE_SOURCE_DIR}/thirdparty)

# Build information
OPTION(BUILD_SHARED_LIBS "BUILD Shared Library" OFF)

# N2n specific params
OPTION(N2N_OPTION_USE_PTHREAD "USE PTHREAD Library" OFF)
OPTION(N2N_OPTION_USE_OPENSSL "USE OPENSSL Library" OFF)
OPTION(N2N_OPTION_USE_CAPLIB "USE CAP Library" OFF)
OPTION(N2N_OPTION_USE_PCAPLIB "USE PCAP Library" OFF)
OPTION(N2N_OPTION_USE_ZSTD "USE ZSTD Library" OFF)
OPTION(N2N_OPTION_USE_PORTMAPPING "USE MINIUPNP and NATPMP Libraries" OFF)


if(N2N_OPTION_USE_PTHREAD)
  find_library(PTHREAD_LIB pthread)
  if(NOT PTHREAD_LIB)
    MESSAGE(FATAL_ERROR "libpthread not found.")
  endif(NOT PTHREAD_LIB)
  MESSAGE(STATUS "Using libpthread.")
  ADD_DEFINITIONS("-DHAVE_PTHREAD")
endif(N2N_OPTION_USE_PTHREAD)

if(N2N_OPTION_USE_OPENSSL)
  find_package(OpenSSL QUIET)
  if(NOT OPENSSL_FOUND)
      MESSAGE(FATAL_ERROR "OpenSSL not found.")
  endif(NOT OPENSSL_FOUND)
  MESSAGE(STATUS "Found OpenSSL ${OPENSSL_VERSION}")
  string(COMPARE GREATER "${OPENSSL_VERSION}" "1.1"  OPENSSL_V11)
  if(NOT OPENSSL_V11)
      MESSAGE(FATAL_ERROR "OpenSSL too old")
  endif()
  include_directories(${OPENSSL_INCLUDE_DIR})
  add_definitions(-DHAVE_OPENSSL_1_1)
endif(N2N_OPTION_USE_OPENSSL)

if(N2N_OPTION_USE_ZSTD)
  find_library(LIBZSTD zstd)
  if(NOT LIBZSTD)
    MESSAGE(FATAL_ERROR "libzstd not found.")
  endif(NOT LIBZSTD)
  MESSAGE(STATUS "Using libztd.")
  add_definitions(-DHAVE_ZSTD)
endif(N2N_OPTION_USE_ZSTD)

if(N2N_OPTION_USE_PCAPLIB)
  find_library(PCAP_LIB pcap)
  if(NOT PCAP_LIB)
    MESSAGE(FATAL_ERROR "libpcap not found.")
  endif(NOT PCAP_LIB)

  # Set var needed for check_function_exists()
  set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIB})

  # TODO
  # - pcap_set_immediate_mode has been available since libpcap 1.5 in 2013
  #   probably should remove this check
  check_function_exists(pcap_set_immediate_mode HAVE_PCAP_IMMEDIATE_MODE)
  IF(NOT HAVE_PCAP_IMMEDIATE_MODE)
    MESSAGE(FATAL_ERROR "libpcap not support pcap_set_immediate_mode()")
  ENDIF(NOT HAVE_PCAP_IMMEDIATE_MODE)
  MESSAGE(STATUS "Using libpcap.")

  ADD_DEFINITIONS("-DHAVE_PCAP_IMMEDIATE_MODE")
  add_executable(n2n-decode tools/n2n-decode.c)
  target_link_libraries(n2n-decode n2n pcap)
  install(TARGETS n2n-decode RUNTIME DESTINATION bin)

endif(N2N_OPTION_USE_PCAPLIB)

if(N2N_OPTION_USE_CAPLIB)
  # Linux Capabilities
  find_library(CAP_LIB cap)
  if(NOT CAP_LIB)
    MESSAGE(FATAL_ERROR "libcap not found.")
  endif(NOT CAP_LIB)
  MESSAGE(STATUS "Using libcap.")

  ADD_DEFINITIONS("-DHAVE_LIBCAP")

endif(N2N_OPTION_USE_CAPLIB)

if(N2N_OPTION_USE_PORTMAPPING)
  ADD_DEFINITIONS("-DHAVE_MINIUPNP")
  include_directories(${THIRD_PARTY_DIR}/miniupnp/miniupnpc/include)
  add_subdirectory(${THIRD_PARTY_DIR}/miniupnp/miniupnpc lib_miniupnpc)
  link_directories(${PROJECT_BINARY_DIR}/lib_miniupnpc)

  ADD_DEFINITIONS("-DHAVE_NATPMP")
  include_directories(${THIRD_PARTY_DIR}/libnatpmp)
  add_subdirectory(${THIRD_PARTY_DIR}/libnatpmp libnatpmp)
  link_directories(${PROJECT_BINARY_DIR}/libnatpmp)

  # Turns on the generic code for supporting either of the above
  ADD_DEFINITIONS("-DHAVE_PORT_FORWARDING")

  # TODO:
  # - this is the odd one out, is it needed?
  include_directories(${PROJECT_BINARY_DIR}/lib_miniupnpc)
endif(N2N_OPTION_USE_PORTMAPPING)


if(NOT DEFINED CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE None)
endif(NOT DEFINED CMAKE_BUILD_TYPE)
#set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE Release)

if (DEFINED UNIX)
# None
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wshadow -Wpointer-arith -Wmissing-declarations -Wnested-externs")
set(CMAKE_CXX_FLAGS "-Wall -Wshadow -Wpointer-arith -Wmissing-declarations -Wnested-externs")
# Debug
set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
# Release
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
endif(DEFINED UNIX)

# Static target.
#SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static")


INCLUDE_DIRECTORIES(.)
INCLUDE_DIRECTORIES(include)
if(DEFINED WIN32)
  INCLUDE_DIRECTORIES(win32)
#  Customize include.
#  INCLUDE_DIRECTORIES("D:/Program Files/MinGW/opt/include/" "D:/Program Files/MinGW/x86_64-w64-mingw32/include/")
#  Customize library.
#  LINK_DIRECTORIES("D:/Program Files/MinGW/opt/lib/" "D:/Program Files/MinGW/x86_64-w64-mingw32/lib/")
endif(DEFINED WIN32)


#aux_source_directory(./src N2N_DIR_SRCS)
#add_library(n2n STATIC ${N2N_DIR_SRCS})
add_library(n2n STATIC
        src/n2n.c
        src/edge_management.c
        src/edge_utils.c
        src/sn_management.c
        src/sn_utils.c
        src/wire.c
        src/hexdump.c
        src/minilzo.c
        src/tf.c
        src/cc20.c
        src/transform_null.c
        src/transform_tf.c
        src/transform_aes.c
        src/transform_cc20.c
        src/transform_speck.c
        src/transform_lzo.c
        src/transform_zstd.c
        src/aes.c
        src/speck.c
        src/random_numbers.c
        src/pearson.c
        src/header_encryption.c
        src/tuntap_freebsd.c
        src/tuntap_netbsd.c
        src/tuntap_linux.c
        src/tuntap_osx.c
        src/n2n_regex.c
        src/network_traffic_filter.c
        src/sn_selection.c
        src/auth.c
        src/curve25519.c
        src/n2n_port_mapping.c)


if(DEFINED WIN32)
  add_library(edge_utils_win32 src/edge_utils_win32.c)
  add_subdirectory(win32)
  target_link_libraries(n2n edge_utils_win32 n2n_win32 iphlpapi)
endif(DEFINED WIN32)

add_executable(edge src/edge.c)
target_link_libraries(edge n2n)

add_executable(supernode src/supernode.c)
target_link_libraries(supernode n2n)

add_executable(example_edge_embed_quick_edge_init src/example_edge_embed_quick_edge_init.c)
target_link_libraries(example_edge_embed_quick_edge_init n2n)

add_executable(example_edge_embed src/example_edge_embed.c)
target_link_libraries(example_edge_embed n2n)

add_executable(example_sn_embed src/example_sn_embed.c)
target_link_libraries(example_sn_embed n2n)

if(N2N_OPTION_USE_PTHREAD)
  target_link_libraries(n2n pthread)
endif(N2N_OPTION_USE_PTHREAD)

if(N2N_OPTION_USE_OPENSSL)
#  target_link_libraries(n2n crypto)
  target_link_libraries(n2n ${OPENSSL_LIBRARIES})
endif(N2N_OPTION_USE_OPENSSL)

if(N2N_OPTION_USE_ZSTD)
  target_link_libraries(n2n zstd)
endif(N2N_OPTION_USE_ZSTD)

if(N2N_OPTION_USE_CAPLIB)
  # TODO: this is a static library, shouldnt we have a generic one?
  target_link_libraries(edge cap.a)
endif(N2N_OPTION_USE_CAPLIB)

if(N2N_OPTION_USE_PORTMAPPING)
  target_link_libraries(n2n libminiupnpc-static)
  target_link_libraries(n2n natpmp)
endif(N2N_OPTION_USE_PORTMAPPING)

install(TARGETS edge supernode
        RUNTIME DESTINATION sbin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
       )


# Tools
add_executable(n2n-benchmark tools/n2n-benchmark.c)
target_link_libraries(n2n-benchmark n2n)
add_executable(n2n-keygen tools/n2n-keygen.c)
target_link_libraries(n2n-keygen n2n)

add_executable(tests-auth tools/tests-auth.c)
target_link_libraries(tests-auth n2n)
add_executable(tests-compress tools/tests-compress.c)
target_link_libraries(tests-compress n2n)
add_executable(tests-elliptic tools/tests-elliptic.c)
target_link_libraries(tests-elliptic n2n)
add_executable(tests-hashing tools/tests-hashing.c)
target_link_libraries(tests-hashing n2n)
add_executable(tests-transform tools/tests-transform.c)
target_link_libraries(tests-transform n2n)
add_executable(tests-wire tools/tests-wire.c)
target_link_libraries(tests-wire n2n)

install(TARGETS n2n-benchmark RUNTIME DESTINATION bin)

# Documentation
if(DEFINED UNIX)
add_dependencies(n2n doc)
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/doc)
add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/doc/edge.8.gz
                   COMMAND gzip -c ${PROJECT_SOURCE_DIR}/edge.8 > ${PROJECT_BINARY_DIR}/doc/edge.8.gz
                   DEPENDS ${PROJECT_SOURCE_DIR}/edge.8
                  )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                   COMMAND gzip -c ${PROJECT_SOURCE_DIR}/supernode.1 > ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                   DEPENDS ${PROJECT_SOURCE_DIR}/supernode.1
                  )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/doc/n2n.7.gz
                   COMMAND gzip -c ${PROJECT_SOURCE_DIR}/n2n.7 > ${PROJECT_BINARY_DIR}/doc/n2n.7.gz
                   DEPENDS ${PROJECT_SOURCE_DIR}/n2n.7
                  )

add_custom_target(doc DEPENDS ${PROJECT_BINARY_DIR}/doc/edge.8.gz
                              ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                              ${PROJECT_BINARY_DIR}/doc/n2n.7.gz
                 )

set_source_files_properties(${PROJECT_BINARY_DIR}/doc/edge.8.gz
                            ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                            ${PROJECT_BINARY_DIR}/doc/n2n.7.gz
                            PROPERTIES GENERATED 1)

install(FILES ${PROJECT_BINARY_DIR}/doc/edge.8.gz
        DESTINATION /usr/share/man/man8)
install(FILES ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
        DESTINATION /usr/share/man/man1)
install(FILES ${PROJECT_BINARY_DIR}/doc/n2n.7.gz
        DESTINATION /usr/share/man/man7)
endif(DEFINED UNIX)

if (CMAKE_SYSTEM_NAME STREQUAL Linux)

# TODO:
# - Add the right dependancy so that the tests binaries get built first
enable_testing()
add_test(NAME unit
    COMMAND ${CMAKE_COMMAND} -E env
        TOPDIR=${PROJECT_SOURCE_DIR} BINDIR=${PROJECT_BINARY_DIR}
        ${PROJECT_SOURCE_DIR}/scripts/test_harness.sh ${PROJECT_SOURCE_DIR}/tests/tests_units.list
)
add_test(NAME integration
    COMMAND ${CMAKE_COMMAND} -E env
        TOPDIR=${PROJECT_SOURCE_DIR} BINDIR=${PROJECT_BINARY_DIR}
        ${PROJECT_SOURCE_DIR}/scripts/test_harness.sh ${PROJECT_SOURCE_DIR}/tests/tests_integration.list
)
endif()
