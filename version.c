#ifndef WIN32
#include "config.h"
#else
#include "win32/winconfig.h"
#endif

const char * n2n_sw_version   = PACKAGE_VERSION;
const char * n2n_sw_osName    = PACKAGE_OSNAME;
const char * n2n_sw_buildDate = __DATE__ " " __TIME__;
