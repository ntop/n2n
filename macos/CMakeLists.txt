add_library(n2n_macos
            utun.c
            arp.c
            route.c)

target_include_directories(n2n_macos PUBLIC ${CMAKE_SOURCE_DIR}/include)
