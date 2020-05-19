
include $(top_srcdir)/Makefile.tool-tests.am

dist_noinst_SCRIPTS = filter_stderr filter_pts dump_stdout filter_sigwait

EXTRA_DIST = \
	statvfs.vgtest \
	statvfs.stderr.exp \
	statvfs.stderr.exp-x86 \
	pdfork_pdkill.vgtest \
	pdfork_pdkill.stderr.exp \
	pdfork_pdkill.stderr.exp-pts \
	getfsstat.vgtest \
	getfsstat.stderr.exp \
	supponlyobj.vgtest \
	supponlyobj.stderr.exp \
	extattr.vgtest \
	extattr.stderr.exp \
	sigwait.vgtest \
	sigwait.stdout.exp \
	sigwait.stderr.exp \
	chflags.vgtest\
	chflags.stderr.exp

check_PROGRAMS = \
	statvfs pdfork_pdkill getfsstat inlinfo inlinfo_nested.so extattr sigwait chflags

AM_CFLAGS   += $(AM_FLAG_M3264_PRI)
AM_CXXFLAGS += $(AM_FLAG_M3264_PRI)

inlinfo_SOURCES = inlinfo.c
inlinfo_DEPENDENCIES = inlinfo_nested.so
inlinfo_LDFLAGS = -Wl,-rpath,$(top_builddir)/memcheck/tests/freebsd
inlinfo_LDADD = inlinfo_nested.so
inlinfo_nested_so_SOURCES = inlinfo_nested.c
inlinfo_nested_so_CFLAGS = $(AM_CFLAGS) -fPIC @FLAG_W_NO_UNINITIALIZED@
inlinfo_nested_so_LDFLAGS = -Wl,-rpath,$(top_builddir)/memcheck/tests/freebsd -shared -fPIC
