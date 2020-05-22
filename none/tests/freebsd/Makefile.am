
include $(top_srcdir)/Makefile.tool-tests.am

dist_noinst_SCRIPTS = filter_stderr
EXTRA_DIST = \
	auxv.vgtest \
	auxv.stderr.exp

check_PROGRAMS = \
	auxv

AM_CFLAGS   += $(AM_FLAG_M3264_PRI)
AM_CXXFLAGS += $(AM_FLAG_M3264_PRI)
