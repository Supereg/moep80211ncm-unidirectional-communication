
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

check_simulator_LDADD = $(top_builddir)/src/libsimulator.la @CHECK_LIBS@
