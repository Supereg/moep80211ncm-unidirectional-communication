AM_CFLAGS = -O2 -Wall

bin_PROGRAMS = ncm_simulator

ncm_simulator_SOURCES  = src/ncm_simulator.c

ncm_simulator_CPPFLAGS  = $(LIBMOEP_CFLAGS)
ncm_simulator_CPPFLAGS += $(LIBMOEPCOMMON_CFLAGS)
ncm_simulator_CPPFLAGS += $(LIBMOEPGF_CFLAGS)
ncm_simulator_CPPFLAGS += $(LIBMOEPRLNC_CFLAGS)

ncm_simulator_LDADD  = $(LIBMOEP_LIBS)
ncm_simulator_LDADD += $(LIBMOEPGF_LIBS)
ncm_simulator_LDADD += $(LIBMOEPRLNC_LIBS)

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
