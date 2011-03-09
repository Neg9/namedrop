#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)

AC_INIT([namedrop], [0.2.3], [osace-users@lists.sourceforge.net])
AC_CONFIG_SRCDIR([readconf.h])
AC_CONFIG_HEADERS([config.h:config.h.in])

# Checks for programs.
AC_PROG_CC
AC_PROG_LN_S

# Checks for libraries.
AC_CHECK_LIB([cares], [ares_init],
[export HAVE_C_ARES=1;export EXTRA_SRCS=myadns.c;export EXTRA_LIBS=-lcares], [export HAVE_C_ARES=0;export EXTRA_SRCS=;export EXTRA_LIBS=])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h limits.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([memset select strcasecmp strdup strrchr strerror getnameinfo getaddrinfo])

AC_C_BIGENDIAN([export BIGENDIAN=1], [export BIGENDIAN=0], [AC_MSG_ERROR(unable to determine endianness of this machine, hopefully you arent using a pdp-11, if you are i spit in your general direction, otherwise sorry.)])

AC_CHECK_MEMBER([struct sockaddr.sa_len], [AC_DEFINE(HAVE_STRUCT_SOCKADDR_LEN)], [], [#include <sys/types.h>
#include <sys/socket.h>])

AC_SUBST(HAVE_C_ARES)
AC_SUBST(EXTRA_SRCS)
AC_SUBST(EXTRA_LIBS)
AC_SUBST(BIGENDIAN)

AC_PATH_PROGS(USE_MAKE, gmake gnumake make)

AC_CONFIG_FILES([Makefile.inc
		Makefile])
AC_OUTPUT

if test $HAVE_C_ARES -eq 0; then
	echo Warning, no c-ares library detected, try downloading it and re-running configure, or see README if you belive this is an error
fi
