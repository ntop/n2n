odnl> Do not add anything above
AC_INIT([edge], m4_esyscmd([scripts/version.sh | tr -d '\n']))
dnl> Do not add anything above

AC_DEFINE([PACKAGE_BUILDDATE], "[m4_esyscmd([scripts/version.sh date | tr -d '\n'])]", [Last change date])

# Older versions of the autotools expect to find install-sh here.
AC_CONFIG_AUX_DIR(scripts)

AC_CANONICAL_HOST
AC_PROG_CC
AC_CHECK_TOOL([AR], [ar], [false])
AC_CHECK_TOOL([WINDRES], [windres], [windres])

case "$host_os" in
    solaris*)
        # Was in Makefile with the test `uname` -eq "SunOS"
        # and comment "For OpenSolaris (Solaris too?)"
        LIBS="-lsocket -lnsl $LIBS"
        ;;
    mingw*)
        LIBS="-lnetapi32 -lws2_32 -liphlpapi $LIBS"
        EXE=".exe"
        ;;
    *)
        EXE=""
        ;;
esac

# This replicates the old config logic from the Makefile.
# TODO: remove all this and just use the autotools default prefix
# (which is "/usr/local")
case "$host_os" in
    darwin*)
        ;;
    *)
        AC_PREFIX_DEFAULT(/usr)
        ;;
esac

# TODO: ideally, should use AC_ARG_ENABLE
AC_ARG_WITH([edgex],
    AS_HELP_STRING([--with-edgex], [Build for Ubiquity-X]),
    [], [with_edgex=no])
AS_IF([test "x$with_edgex" != "xno"],
    [
        AC_MSG_NOTICE([Please contact us with your use case])
        CC=mipsel-linux-gnu-gcc
        AR=mipsel-linux-gnu-arzls
    ],
)

# TODO: ideally, should use AC_ARG_ENABLE
AC_ARG_WITH([zstd],
    AS_HELP_STRING([--with-zstd], [use zstd library]),
    [], [with_zstd=no])
AS_IF([test "x$with_zstd" != "xno"],
    [AC_CHECK_LIB([zstd], [ZSTD_compress],,
        [AC_MSG_ERROR([zstd library not found])]
    )],
)

# TODO: ideally, should use AC_ARG_ENABLE
AC_ARG_WITH([openssl],
    [AS_HELP_STRING([--with-openssl], [enable support for OpenSSL])],
    [], [with_openssl=no])
AS_IF([test "x$with_openssl" != xno],
    [AC_CHECK_LIB([crypto], [EVP_CIPHER_CTX_reset],,
        [AC_MSG_ERROR([openssl library not found])]
    )],
)

AC_ARG_ENABLE([miniupnp],
    [AS_HELP_STRING([--enable-miniupnp], [support for miniupnp])],
    [], [enable_miniupnp=no])
AS_IF([test "x$enable_miniupnp" != xno],
    [AC_CHECK_LIB([miniupnpc], [upnpDiscover],,
        [AC_MSG_ERROR([miniupnp library not found])]
    )],
)

AC_ARG_ENABLE([natpmp],
    [AS_HELP_STRING([--enable-natpmp], [support for natpmp])],
    [], [enable_natpmp=no])
AS_IF([test "x$enable_natpmp" != xno],
    [AC_CHECK_LIB([natpmp], [initnatpmp],,
        [AC_MSG_ERROR([natpmp library not found])]
    )],
)

AC_ARG_ENABLE([pcap],
    [AS_HELP_STRING([--enable-pcap], [support for pcap])],
    [], [enable_pcap=no])
AS_IF([test "x$enable_pcap" != xno],
    [AC_CHECK_LIB([pcap], [pcap_set_immediate_mode],,
        [AC_MSG_ERROR([pcap library not found])]
    )],
)

AC_ARG_ENABLE([cap],
    [AS_HELP_STRING([--enable-cap], [support for cap])],
    [], [enable_cap=no])
AS_IF([test "x$enable_cap" != xno],
    [AC_CHECK_LIB([cap], [cap_get_proc],,
        [AC_MSG_ERROR([cap library not found])]
    )],
)

AC_ARG_ENABLE([pthread],
    [AS_HELP_STRING([--enable-pthread], [support for pthread])],
    [], [enable_pthread=no])
AS_IF([test "x$enable_pthread" != xno],
    [AC_CHECK_LIB([pthread], [pthread_mutex_trylock],,
        [AC_MSG_ERROR([pthread library not found])]
    )],
)


AC_SUBST(host)
AC_SUBST(host_os)
AC_SUBST(EXE)
AC_SUBST(WINDRES)
AC_CONFIG_HEADERS(include/config.h)
AC_CONFIG_FILES(config.mak)

AC_OUTPUT
