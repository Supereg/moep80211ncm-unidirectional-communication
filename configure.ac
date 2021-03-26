AC_INIT([Moep80211 NCM], [0.0], [moepi@moepi.net], [moep80211ncm], [http://moep80211.net])
#AC_PREREQ([2.69])

AC_PROG_CC
AC_PROG_LN_S

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability subdir-objects foreign])
AM_SILENT_RULES([yes])

AM_PROG_AR
AM_PROG_CC_C_O	# Needed for some buggy automake versions

AC_SUBST(AR_FLAGS, [cr]) # Fixes ar warning during make

LT_INIT([disable-shared])

PKG_CHECK_MODULES([LIBMOEP], [libmoep >= 2.0])
PKG_CHECK_MODULES([CHECK], [check >= 0.10.0])

AC_SEARCH_LIBS([exp], [m])
AC_SEARCH_LIBS([timer_create], [rt])
AC_SEARCH_LIBS([timer_delete], [rt])
AC_SEARCH_LIBS([timer_settime], [rt])
AC_SEARCH_LIBS([timer_gettime], [rt])

LIBMOEPCOMMON_CFLAGS="-I\$(top_srcdir)/libmoepcommon/include"
AC_SUBST(LIBMOEPCOMMON_CFLAGS)

LIBMOEPGF_CFLAGS="-I\$(top_srcdir)/libmoepgf/include"
AC_SUBST(LIBMOEPGF_CFLAGS)
LIBMOEPGF_LIBS="\$(top_builddir)/libmoepgf/libmoepgf.la"
AC_SUBST(LIBMOEPGF_LIBS)

LIBMOEPRLNC_CFLAGS="-I\$(top_srcdir)/libmoeprlnc/include"
AC_SUBST(LIBMOEPRLNC_CFLAGS)
LIBMOEPRLNC_LIBS="\$(top_builddir)/libmoeprlnc/libmoeprlnc.la"
AC_SUBST(LIBMOEPRLNC_LIBS)

LIBJSM_CFLAGS="-I\$(top_srcdir)/libjsm/include"
AC_SUBST(LIBJSM_CFLAGS)
LIBJSM_LIBS="\$(top_builddir)/libjsm/libjsm.la"
AC_SUBST(LIBJSM_LIBS)

AX_CODE_COVERAGE

# Refer to https://github.com/tpm2-software/tpm2-abrmd/pull/574 for
# more details about the madness here.
# Basically what happened is that autoconf-archive version >= 2019.01.06
# introduced a breaking change (see link in reference issue).
# The replaced @CODE_COVERAGE_RULES@ with include $(top_srcdir)/aminclude_static.am
# Thing is aminclude_static.am includes some no-protability warning
# which is the reason why we added -Wno-portability above.
# I don't really understand enough about autoconf to assess
# if that's a good or a bad thing.
m4_ifdef([_AX_CODE_COVERAGE_RULES],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [true])],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [false])])
AX_ADD_AM_MACRO_STATIC([]) # related https://github.com/tpm2-software/tpm2-tss/pull/1256

AS_IF([test x$enable_code_coverage != xno], [
	# autoconf default cflags are "-g -O2" which overrides our -O0 for code coverage testing
	# This is a workaround to override the default -02
	CFLAGS="$CFLAGS -O0"
	AC_SEARCH_LIBS(gcov_open, gcov)
])

AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])

AC_CONFIG_SUBDIRS([libmoepgf libmoeprlnc libjsm])

AC_OUTPUT
