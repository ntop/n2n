add_library(n2n_win32
            getopt1.c
            getopt.c
            wintap.c)
target_link_libraries(n2n_win32 PUBLIC ws2_32.lib)
