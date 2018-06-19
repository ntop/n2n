project(Hin2n)
cmake_minimum_required(VERSION 3.4.1)

# N2n information
set(N2N_VERSION 2.1.0)
set(N2N_OSNAME ${CMAKE_SYSTEM})

INCLUDE(TestBigEndian)
TEST_BIG_ENDIAN(UIP_CONF_BYTE_ORDER)
if(${UIP_CONF_BYTE_ORDER} EQUAL 1)
set(UIP_CONF_BYTE_ORDER UIP_BIG_ENDIAN)
else(${UIP_CONF_BYTE_ORDER} EQUAL 1)
set(UIP_CONF_BYTE_ORDER UIP_LITTLE_ENDIAN)
endif(${UIP_CONF_BYTE_ORDER} EQUAL 1)


if(CMAKE_BUILD_TYPE)
if(NOT ${CMAKE_BUILD_TYPE} STREQUAL Debug)
set(CMAKE_BUILD_TYPE Release)
endif(NOT ${CMAKE_BUILD_TYPE} STREQUAL Debug)
else(CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE Release)
endif(CMAKE_BUILD_TYPE)


add_definitions(-DN2N_VERSION=\"${N2N_VERSION}\" -DN2N_OSNAME=\"${N2N_OSNAME}\" -DUIP_CONF_BYTE_ORDER=\"${UIP_CONF_BYTE_ORDER}\")
include_directories(src/main/cpp src/main/cpp/tun2tap src/main/cpp/uip)

add_library(edge SHARED
                src/main/cpp/n2n/android/edge_jni.c
                src/main/cpp/n2n/android/edge_android.c
            )
target_link_libraries(edge n2n)
target_link_libraries(edge log)

add_library(n2n SHARED
                src/main/cpp/n2n/n2n.c
                src/main/cpp/n2n/n2n_keyfile.c
                src/main/cpp/n2n/wire.c
                src/main/cpp/n2n/minilzo.c
                src/main/cpp/n2n/twofish.c
                src/main/cpp/n2n/edge_utils.c
                src/main/cpp/n2n/transform_null.c
                src/main/cpp/n2n/transform_tf.c
                src/main/cpp/n2n/transform_aes.c
                src/main/cpp/n2n/android/tuntap_android.c
                src/main/cpp/n2n/version.c
            )
target_link_libraries(n2n uip)
target_link_libraries(n2n log)

add_library(uip SHARED
                src/main/cpp/uip/uip.c
                src/main/cpp/uip/uip_arp.c
                src/main/cpp/tun2tap/tun2tap.c
            )
