AM_CFLAGS = -O2 -Wall

@CODE_COVERAGE_RULES@

lib_LTLIBRARIES = libsimulator.la

libsimulator_la_SOURCES  = generation.c
libsimulator_la_SOURCES += generation.h
libsimulator_la_SOURCES += session.c
libsimulator_la_SOURCES += session.h

libsimulator_la_CPPFLAGS  = $(LIBMOEP_CFLAGS)
libsimulator_la_CPPFLAGS += $(LIBMOEPCOMMON_CFLAGS)
libsimulator_la_CPPFLAGS += $(LIBMOEPGF_CFLAGS)
libsimulator_la_CPPFLAGS += $(LIBMOEPRLNC_CFLAGS)

libsimulator_la_LIBADD  = $(LIBMOEP_LIBS)
libsimulator_la_LIBADD += $(LIBMOEPGF_LIBS)
libsimulator_la_LIBADD += $(LIBMOEPRLNC_LIBS)


bin_PROGRAMS = ncm_simulator

ncm_simulator_SOURCES  = ncm_simulator.c

ncm_simulator_CPPFLAGS  = $(LIBMOEP_CFLAGS)
ncm_simulator_CPPFLAGS += $(LIBMOEPCOMMON_CFLAGS)
ncm_simulator_CPPFLAGS += $(LIBMOEPGF_CFLAGS)
ncm_simulator_CPPFLAGS += $(LIBMOEPRLNC_CFLAGS)

ncm_simulator_LDADD  = libsimulator.la
ncm_simulator_LDADD += $(LIBMOEP_LIBS)
ncm_simulator_LDADD += $(LIBMOEPGF_LIBS)
ncm_simulator_LDADD += $(LIBMOEPRLNC_LIBS)


noinst_HEADERS  = ../../libmoepcommon/include/moepcommon/benchmark.h
noinst_HEADERS += ../../libmoepcommon/include/moepcommon/list.h
noinst_HEADERS += ../../libmoepcommon/include/moepcommon/list_sort.h
noinst_HEADERS += ../../libmoepcommon/include/moepcommon/timeout.h
noinst_HEADERS += ../../libmoepcommon/include/moepcommon/types.h
noinst_HEADERS += ../../libmoepcommon/include/moepcommon/util.h
noinst_HEADERS += ../../libmoepcommon/include/moepcommon/util/alignment.h
noinst_HEADERS += ../../libmoepcommon/include/moepcommon/util/assertion.h
noinst_HEADERS += ../../libmoepcommon/include/moepcommon/util/hexdump.h
noinst_HEADERS += ../../libmoepcommon/include/moepcommon/util/log.h
noinst_HEADERS += ../../libmoepcommon/include/moepcommon/util/mac.h
noinst_HEADERS += ../../libmoepcommon/include/moepcommon/util/maths.h
noinst_HEADERS += ../../libmoepcommon/include/moepcommon/util/timespec.h

# a bit ugly, but works for now
noinst_HEADERS += ../../src/global.h
