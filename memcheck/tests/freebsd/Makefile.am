
include $(top_srcdir)/Makefile.tool-tests.am

dist_noinst_SCRIPTS = filter_stderr filter_pts dump_stdout

EXTRA_DIST = \
	statvfs.vgtest \
	statvfs.stderr.exp \
	statvfs.stderr.exp-x86 \
	pdfork_pdkill.vgtest \
	pdfork_pdkill.stderr.exp \
	pdfork_pdkill.stderr.exp-pts \
	getfsstat.vgtest \
	getfsstat.stderr.exp

check_PROGRAMS = \
	statvfs pdfork_pdkill getfsstat

AM_CFLAGS   += $(AM_FLAG_M3264_PRI)
AM_CXXFLAGS += $(AM_FLAG_M3264_PRI)
