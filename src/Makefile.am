
AM_CFLAGS = -O2 -Wall

@CODE_COVERAGE_RULES@

# The session code is used withing the ncm module
# as well as the unit test binary.
# Thus we compile a libtools library containing
# the session submodule, which is then linked to
# both the ncm module as well as the unit tests
lib_LTLIBRARIES = libsession.la

libsession_la_SOURCES  = generation.c
libsession_la_SOURCES += generation.h
libsession_la_SOURCES += session.c
libsession_la_SOURCES += session.h
libsession_la_SOURCES += global.h
libsession_la_SOURCES += params.h

libsession_la_CFLAGS  = $(CODE_COVERAGE_CFLAGS)

libsession_la_CPPFLAGS  = $(LIBMOEP_CFLAGS)
libsession_la_CPPFLAGS += $(LIBMOEPCOMMON_CFLAGS)
libsession_la_CPPFLAGS += $(LIBMOEPGF_CFLAGS)
libsession_la_CPPFLAGS += $(LIBMOEPRLNC_CFLAGS)
libsession_la_CPPFLAGS += $(CODE_COVERAGE_CPPFLAGS)

libsession_la_LIBADD  = $(LIBMOEP_LIBS)
libsession_la_LIBADD += $(LIBMOEPGF_LIBS)
libsession_la_LIBADD += $(LIBMOEPRLNC_LIBS)
libsession_la_LIBADD += $(CODE_COVERAGE_LIBS)


bin_PROGRAMS = $(top_builddir)/ncm

__top_builddir__ncm_SOURCES  = bcast.c
__top_builddir__ncm_SOURCES += bcast.h
__top_builddir__ncm_SOURCES += daemonize.c
__top_builddir__ncm_SOURCES += daemonize.h
__top_builddir__ncm_SOURCES += frametypes.h
__top_builddir__ncm_SOURCES += global.h
__top_builddir__ncm_SOURCES += ncm.c
__top_builddir__ncm_SOURCES += ncm.h
__top_builddir__ncm_SOURCES += neighbor.c
__top_builddir__ncm_SOURCES += neighbor.h
__top_builddir__ncm_SOURCES += linkstate.c
__top_builddir__ncm_SOURCES += linkstate.h
__top_builddir__ncm_SOURCES += params.h
__top_builddir__ncm_SOURCES += ralqe.c
__top_builddir__ncm_SOURCES += ralqe.h
__top_builddir__ncm_SOURCES += qdelay.c
__top_builddir__ncm_SOURCES += qdelay.h

__top_builddir__ncm_CPPFLAGS  = $(LIBMOEP_CFLAGS)
__top_builddir__ncm_CPPFLAGS += $(LIBMOEPCOMMON_CFLAGS)
__top_builddir__ncm_CPPFLAGS += $(LIBMOEPGF_CFLAGS)
__top_builddir__ncm_CPPFLAGS += $(LIBMOEPRLNC_CFLAGS)
__top_builddir__ncm_CPPFLAGS += $(LIBJSM_CFLAGS)

__top_builddir__ncm_LDADD  = $(LIBMOEP_LIBS)
__top_builddir__ncm_LDADD += $(LIBMOEPGF_LIBS)
__top_builddir__ncm_LDADD += $(LIBMOEPRLNC_LIBS)
__top_builddir__ncm_LDADD += $(LIBJSM_LIBS)
__top_builddir__ncm_LDADD += libsession.la

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
