
include $(top_srcdir)/Makefile.tool-tests.am

dist_noinst_SCRIPTS = filter_stderr filter_pts

EXTRA_DIST = \
	statvfs.vgtest \
	statvfs.stderr.exp \
	pdfork_pdkill.vgtest \
	pdfork_pdkill.stderr.exp

check_PROGRAMS = \
	statvfs pdfork_pdkill

AM_CFLAGS   += $(AM_FLAG_M3264_PRI)
AM_CXXFLAGS += $(AM_FLAG_M3264_PRI)
