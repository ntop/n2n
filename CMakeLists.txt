project(n2n)
cmake_minimum_required(VERSION 2.6)
include(CheckFunctionExists)
SET(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# N2n release information
set(N2N_VERSION "3.0.0")
set(N2N_OSNAME ${CMAKE_SYSTEM_NAME})
execute_process(
        COMMAND git status
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_OUTPUT
        RESULT_VARIABLE GIT_ERROR_CODE
)
if (GIT_ERROR_CODE EQUAL 0)
execute_process(
        COMMAND git rev-list --count HEAD
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_REV
)
execute_process(
        COMMAND git rev-parse --short HEAD
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_ID
)
string(REGEX REPLACE "\n$" "" GIT_REV "${GIT_REV}")
string(REGEX REPLACE "\n$" "" GIT_ID "${GIT_ID}")
set(N2N_VERSION "${N2N_VERSION}.r${GIT_REV}.${GIT_ID}")
MESSAGE(STATUS "Build from git rev: ${N2N_VERSION}")
endif (GIT_ERROR_CODE EQUAL 0)

add_definitions(-DCMAKE_BUILD)
add_definitions(-DGIT_RELEASE="${N2N_VERSION}" -DPACKAGE_VERSION="${N2N_VERSION}" -DPACKAGE_OSNAME="${N2N_OSNAME}")
add_definitions(-DN2N_VERSION="${N2N_VERSION}" -DN2N_OSNAME="${N2N_OSNAME}")


# Build information
OPTION(BUILD_SHARED_LIBS "BUILD Shared Library" OFF)

# N2n specific params
OPTION(N2N_OPTION_USE_PTHREAD "USE PTHREAD Library" ON)
OPTION(N2N_OPTION_USE_OPENSSL "USE OPENSSL Library" OFF)
OPTION(N2N_OPTION_USE_PCAPLIB "USE PCAP Library" OFF)
OPTION(N2N_OPTION_USE_ZSTD "USE ZSTD Library" OFF)


if(N2N_OPTION_USE_PTHREAD)
  find_library(PTHREAD_LIB pthread)
  if(PTHREAD_LIB)
    ADD_DEFINITIONS("-DHAVE_PTHREAD")
  else()
    MESSAGE(WARNING "libpthread not found.")
    set(N2N_OPTION_USE_PTHREAD OFF)   
  endif(PTHREAD_LIB)
endif(N2N_OPTION_USE_PTHREAD)

if(NOT DEFINED N2N_OPTION_USE_OPENSSL)
set(N2N_OPTION_USE_OPENSSL OFF)
endif(NOT DEFINED N2N_OPTION_USE_OPENSSL)

if(N2N_OPTION_USE_OPENSSL)
  find_package(OpenSSL QUIET)
  if(NOT OPENSSL_FOUND)
    MESSAGE(WARNING "OpenSSL not found, Use built-in AES.")
    set(N2N_OPTION_USE_OPENSSL OFF)
  else()
    MESSAGE(STATUS "Found OpenSSL ${OPENSSL_VERSION}")
    string(COMPARE GREATER "${OPENSSL_VERSION}" "1.1"  OPENSSL_V11)
    if(OPENSSL_V11)
      MESSAGE(STATUS "Use OpenSSL With -DHAVE_OPENSSL_1_1")
      include_directories(${OPENSSL_INCLUDE_DIR})
      add_definitions(-DHAVE_OPENSSL_1_1)
    endif()
  endif(NOT OPENSSL_FOUND)
endif(N2N_OPTION_USE_OPENSSL)

if(N2N_OPTION_USE_ZSTD)
  add_definitions(-DN2N_HAVE_ZSTD)
endif(N2N_OPTION_USE_ZSTD)

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
        src/curve25519.c)


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

if(N2N_OPTION_USE_PCAPLIB AND (NOT DEFINED WIN32))
  # Linux Capabilities
  find_library(CAP_LIB cap)
  if(CAP_LIB)
    target_link_libraries(edge cap.a)
    set(CMAKE_REQUIRED_LIBRARIES ${CAP_LIB})
    ADD_DEFINITIONS("-DHAVE_LIBCAP")
  endif()
endif(N2N_OPTION_USE_PCAPLIB AND (NOT DEFINED WIN32))

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

if(N2N_OPTION_USE_PCAPLIB)
  find_library(PCAP_LIB pcap)
  if(PCAP_LIB)
    add_executable(n2n-decode tools/n2n-decode.c)
    target_link_libraries(n2n-decode n2n pcap)
    install(TARGETS n2n-decode RUNTIME DESTINATION bin)

    set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIB})
    check_function_exists(pcap_set_immediate_mode HAVE_PCAP_IMMEDIATE_MODE)
    IF(HAVE_PCAP_IMMEDIATE_MODE)
      ADD_DEFINITIONS("-DHAVE_PCAP_IMMEDIATE_MODE")
    ENDIF(HAVE_PCAP_IMMEDIATE_MODE)
  endif(PCAP_LIB)
endif(N2N_OPTION_USE_PCAPLIB)

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

# TODO:
# - Add the right dependancy so that the tests binaries get built first
enable_testing()
add_test(tests ${PROJECT_SOURCE_DIR}/scripts/test_harness.sh ${PROJECT_BINARY_DIR} ${PROJECT_SOURCE_DIR}/tests)

endif(DEFINED UNIX)
