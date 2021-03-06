
@CODE_COVERAGE_RULES@

TESTS = check_simulator
check_PROGRAMS = check_simulator

check_simulator_SOURCES  = check_main.c
check_simulator_SOURCES += check_generation.c
check_simulator_SOURCES += check_session.c
check_simulator_SOURCES += check_simulator.h

check_simulator_SOURCES += \$(top_builddir)/src/generation.h
check_simulator_SOURCES += \$(top_builddir)/src/session.h

check_simulator_CFLAGS = @CHECK_CFLAGS@

check_simulator_CPPFLAGS = $(LIBMOEP_CFLAGS)
check_simulator_CPPFLAGS += $(LIBMOEPCOMMON_CFLAGS)
check_simulator_CPPFLAGS += $(LIBMOEPGF_CFLAGS)
check_simulator_CPPFLAGS += $(LIBMOEPRLNC_CFLAGS)

check_simulator_LDADD  = $(top_builddir)/src/libsimulator.la
check_simulator_LDADD += @CHECK_LIBS@
check_simulator_LDADD += $(LIBMOEP_LIBS)
check_simulator_LDADD += $(LIBMOEPGF_LIBS)
check_simulator_LDADD += $(LIBMOEPRLNC_LIBS)

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
