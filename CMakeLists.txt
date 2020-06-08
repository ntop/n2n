project(n2n)
cmake_minimum_required(VERSION 2.6)
include(CheckFunctionExists)

# N2n information
set(N2N_VERSION 2.5.1)
set(N2N_OSNAME ${CMAKE_SYSTEM})

# N2n specific params
OPTION(N2N_OPTION_AES "USE AES" ON)

# Build information
OPTION(BUILD_SHARED_LIBS "BUILD Shared Library" OFF)


if(NOT DEFINED N2N_OPTION_AES)
set(N2N_OPTION_AES ON)
endif(NOT DEFINED N2N_OPTION_AES)

add_definitions(-DCMAKE_BUILD)
add_definitions(-DGIT_RELEASE="" -DPACKAGE_VERSION="${N2N_VERSION}" -DPACKAGE_OSNAME="${CMAKE_SYSTEM}")
add_definitions(-DN2N_VERSION="${N2N_VERSION}" -DN2N_OSNAME="${N2N_OSNAME}")

if(N2N_OPTION_AES)
find_package(OpenSSL REQUIRED)
add_definitions(-DN2N_HAVE_AES)
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
endif()

## DEBUG FOR CMAKE
#message(${N2N_VERSION}) 
#message(${N2N_OSNAME})
##message(${CMAKE_BUILD_TYPE})
#message(${N2N_OPTION_AES})
## DEBUG FOR CMAKE

# Add SHARED to build DLL
add_library(n2n n2n.c
                edge_utils.c
                sn_utils.c
                wire.c
                minilzo.c
                twofish.c
                transform_null.c
                transform_tf.c
                transform_aes.c
		random_numbers.c
                tuntap_freebsd.c
                tuntap_netbsd.c
                tuntap_linux.c
                tuntap_osx.c
            )

if(DEFINED WIN32)
add_subdirectory(win32)
target_link_libraries(n2n n2n_win32)
endif(DEFINED WIN32)

if(N2N_OPTION_AES)
target_link_libraries(n2n ${OPENSSL_LIBRARIES})
include_directories(${OPENSSL_INCLUDE_DIR})
endif(N2N_OPTION_AES)

add_executable(edge edge.c)
target_link_libraries(edge n2n)

add_executable(supernode sn.c)
target_link_libraries(supernode n2n)

add_executable(example_edge_embed_quick_edge_init example_edge_embed_quick_edge_init.c)
target_link_libraries(example_edge_embed_quick_edge_init n2n)

add_executable(example_edge_embed example_edge_embed.c)
target_link_libraries(example_edge_embed n2n)

add_executable(example_sn_embed example_sn_embed.c)
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
include_directories(.)

add_executable(n2n-benchmark tools/benchmark.c)
target_link_libraries(n2n-benchmark n2n ${OPENSSL_LIBRARIES})

find_library(PCAP_LIB pcap)
if(PCAP_LIB)
  add_executable(n2n-decode tools/n2n_decode.c)
  target_link_libraries(n2n-decode n2n pcap)
  install(TARGETS n2n-decode RUNTIME DESTINATION bin)

  set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIB})
  check_function_exists(pcap_set_immediate_mode HAVE_PCAP_IMMEDIATE_MODE)
  IF(HAVE_PCAP_IMMEDIATE_MODE)
    ADD_DEFINITIONS("-DHAVE_PCAP_IMMEDIATE_MODE")
  ENDIF()
endif()

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
