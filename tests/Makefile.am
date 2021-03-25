
# See comment in configure.ac
if AUTOCONF_CODE_COVERAGE_2019_01_06
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean
else
@CODE_COVERAGE_RULES@
endif

TESTS = check_session
check_PROGRAMS = check_session

check_session_SOURCES  = check_main.c
check_session_SOURCES += check_utils.c
check_session_SOURCES += check_utils.h
check_session_SOURCES += check_generation.c
check_session_SOURCES += check_session.c
check_session_SOURCES += check_suites.h

check_session_CFLAGS  = @CHECK_CFLAGS@
check_session_CFLAGS += $(CODE_COVERAGE_CFLAGS)

check_session_CPPFLAGS  = $(LIBMOEP_CFLAGS)
check_session_CPPFLAGS += $(LIBMOEPCOMMON_CFLAGS)
check_session_CPPFLAGS += $(LIBMOEPGF_CFLAGS)
check_session_CPPFLAGS += $(LIBMOEPRLNC_CFLAGS)
check_session_CPPFLAGS += $(CODE_COVERAGE_CPPFLAGS)

check_session_LDADD  = $(top_builddir)/src/libsession.la
check_session_LDADD += @CHECK_LIBS@
check_session_LDADD += $(LIBMOEP_LIBS)
check_session_LDADD += $(LIBMOEPGF_LIBS)
check_session_LDADD += $(LIBMOEPRLNC_LIBS)
check_session_LDADD += $(CODE_COVERAGE_LIBS)

noinst_HEADERS  = ../libmoepcommon/include/moepcommon/benchmark.h
noinst_HEADERS += ../libmoepcommon/include/moepcommon/list.h
noinst_HEADERS += ../libmoepcommon/include/moepcommon/list_sort.h
noinst_HEADERS += ../libmoepcommon/include/moepcommon/timeout.h
noinst_HEADERS += ../libmoepcommon/include/moepcommon/types.h
noinst_HEADERS += ../libmoepcommon/include/moepcommon/util.h
noinst_HEADERS += ../libmoepcommon/include/moepcommon/util/alignment.h
noinst_HEADERS += ../libmoepcommon/include/moepcommon/util/assertion.h
noinst_HEADERS += ../libmoepcommon/include/moepcommon/util/hexdump.h
noinst_HEADERS += ../libmoepcommon/include/moepcommon/util/log.h
noinst_HEADERS += ../libmoepcommon/include/moepcommon/util/mac.h
noinst_HEADERS += ../libmoepcommon/include/moepcommon/util/maths.h
noinst_HEADERS += ../libmoepcommon/include/moepcommon/util/timespec.h
