project(n2n)
cmake_minimum_required(VERSION 2.6)
include(CheckFunctionExists)
SET(CMAKE_VERBOSE_MAKEFILE ON)

# N2n release information
set(N2N_VERSION "2.8.0")
set(N2N_OSNAME ${CMAKE_SYSTEM})
execute_process(
        COMMAND git --version
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_EXIST
)
if (GIT_EXIST)
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
endif (GIT_EXIST)

add_definitions(-DCMAKE_BUILD)
add_definitions(-DGIT_RELEASE="" -DPACKAGE_VERSION="${N2N_VERSION}" -DPACKAGE_OSNAME="${N2N_OSNAME}")
add_definitions(-DN2N_VERSION="${N2N_VERSION}" -DN2N_OSNAME="${N2N_OSNAME}")


# Build information
OPTION(BUILD_SHARED_LIBS "BUILD Shared Library" OFF)

# N2n specific params
OPTION(N2N_OPTION_AES "USE AES" ON)

if(NOT DEFINED N2N_OPTION_AES)
set(N2N_OPTION_AES ON)
endif(NOT DEFINED N2N_OPTION_AES)

if(N2N_OPTION_AES)
  find_package(OpenSSL QUIET)
  if(NOT OPENSSL_FOUND)
    MESSAGE(WARNING "OpenSSL not found, AES disabled.")
    set(N2N_OPTION_AES OFF)
  else()
    include_directories(${OPENSSL_INCLUDE_DIR})
    add_definitions(-DN2N_HAVE_AES)
  endif(NOT OPENSSL_FOUND)
endif(N2N_OPTION_AES)


if(NOT DEFINED CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE None)
endif(NOT DEFINED CMAKE_BUILD_TYPE)
#set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE Release)

if (DEFINED UNIX)
# None
set(CMAKE_C_FLAGS "-Wall -Wshadow -Wpointer-arith -Wmissing-declarations -Wnested-externs")
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
        src/edge_utils.c
        src/sn_utils.c
        src/wire.c
        src/minilzo.c
        src/twofish.c
        src/transform_null.c
        src/transform_tf.c
        src/transform_aes.c
        src/transform_cc20.c
        src/transform_speck.c
        src/speck.c
        src/random_numbers.c
        src/pearson.c
        src/header_encryption.c
        src/tuntap_freebsd.c
        src/tuntap_netbsd.c
        src/tuntap_linux.c
        src/tuntap_osx.c
        )

if(DEFINED WIN32)
  add_library(edge_utils_win32 src/edge_utils_win32.c)
  add_subdirectory(win32)
  target_link_libraries(n2n edge_utils_win32 n2n_win32 )
endif(DEFINED WIN32)

if(N2N_OPTION_AES)
#  target_link_libraries(n2n crypto)
  target_link_libraries(n2n ${OPENSSL_LIBRARIES})
endif(N2N_OPTION_AES)


add_executable(edge src/edge.c)
target_link_libraries(edge n2n)

add_executable(supernode src/sn.c)
target_link_libraries(supernode n2n)

add_executable(example_edge_embed_quick_edge_init src/example_edge_embed_quick_edge_init.c)
target_link_libraries(example_edge_embed_quick_edge_init n2n)

add_executable(example_edge_embed src/example_edge_embed.c)
target_link_libraries(example_edge_embed n2n)

add_executable(example_sn_embed src/example_sn_embed.c)
target_link_libraries(example_sn_embed n2n)

if(NOT DEFINED WIN32)
  # Linux Capabilities
  find_library(CAP_LIB cap)
  if(CAP_LIB)
    target_link_libraries(edge cap)
    set(CMAKE_REQUIRED_LIBRARIES ${CAP_LIB})
    ADD_DEFINITIONS("-DHAVE_LIBCAP")
  endif()
endif(NOT DEFINED WIN32)

install(TARGETS edge supernode
        RUNTIME DESTINATION sbin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
       )


# Tools
add_executable(n2n-benchmark tools/benchmark.c)
target_link_libraries(n2n-benchmark n2n)

find_library(PCAP_LIB pcap)
if(PCAP_LIB)
  add_executable(n2n-decode tools/n2n_decode.c)
  target_link_libraries(n2n-decode n2n pcap)
  install(TARGETS n2n-decode RUNTIME DESTINATION bin)

  set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIB})
  check_function_exists(pcap_set_immediate_mode HAVE_PCAP_IMMEDIATE_MODE)
  IF(HAVE_PCAP_IMMEDIATE_MODE)
    ADD_DEFINITIONS("-DHAVE_PCAP_IMMEDIATE_MODE")
  ENDIF(HAVE_PCAP_IMMEDIATE_MODE)
endif(PCAP_LIB)

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
        DESTINATION /usr/share/man8)
install(FILES ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
        DESTINATION /usr/share/man1)
install(FILES ${PROJECT_BINARY_DIR}/doc/n2n.7.gz
        DESTINATION /usr/share/man7)
endif(DEFINED UNIX)
