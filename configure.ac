odnl> Do not add anything above
AC_INIT([edge],2.5.0)
dnl> Do not add anything above

N2N_VERSION=2.5.0

AC_CHECK_LIB([crypto], [AES_cbc_encrypt])

N2N_LIBS=

if test "x$ac_cv_lib_crypto_AES_cbc_encrypt" != xyes; then
  AC_MSG_RESULT(Building n2n without AES support)
else
  AC_DEFINE([N2N_HAVE_AES], [], [Have AES support])
  N2N_LIBS=-lcrypto
fi

MACHINE=`uname -m`
SYSTEM=`uname -s`

if test $SYSTEM = "Linux"; then
   if test -f /etc/debian_version; then
      DEBIAN_VERSION=`cat /etc/debian_version`
      OSNAME="Debian $DEBIAN_VERSION"
   else
      OSNAME=`./config.guess`
   fi
else
dnl> wget -O config.guess 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess;hb=HEAD'
   OSNAME=`./config.guess`
fi
AC_DEFINE_UNQUOTED(PACKAGE_OSNAME, "${OSNAME}", [OS name])

if test $MACHINE = "x86_64"; then
   EXTN="amd64"
else
   if test $MACHINE = "i686"; then
     EXTN="i386"
   fi
fi

DATE=`date +"%Y-%m-%d"`

AC_SUBST(N2N_VERSION)
AC_SUBST(N2N_DEFINES)
AC_SUBST(N2N_LIBS)
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile)

AC_OUTPUT

