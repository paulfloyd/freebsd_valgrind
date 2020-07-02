
include $(top_srcdir)/Makefile.tool-tests.am

dist_noinst_SCRIPTS = filter_stderr filter_pts dump_stdout filter_sigwait \
	filter_scalar

EXTRA_DIST = \
	statvfs.vgtest \
	statvfs.stderr.exp \
	statvfs.stderr.exp-x86 \
	pdfork_pdkill.vgtest \
	pdfork_pdkill.stderr.exp \
	pdfork_pdkill.stderr.exp-pts \
	getfsstat.vgtest \
	getfsstat.stderr.exp \
		getfsstat.stderr.exp-x86 \
	supponlyobj.vgtest \
	supponlyobj.stderr.exp \
	extattr.vgtest \
	extattr.stderr.exp \
	sigwait.vgtest \
	sigwait.stdout.exp \
	sigwait.stderr.exp \
		sigwait.stderr.exp-x86 \
	chflags.vgtest\
	chflags.stderr.exp \
		chflags.stderr.exp-x86 \
	get_set_login.vgtest \
	get_set_login.stderr.exp \
	revoke.vgtest \
	revoke.stderr.exp \
	scalar.vgtest \
	scalar.stderr.exp \
		scalar.stderr.exp-x86 \
	capsicum.vgtest \
	capsicum.stderr.exp \
	getfh.vgtest \
	getfh.stderr.exp \
	linkat.vgtest \
	linkat.stderr.exp \
	scalar_fork.vgtest \
	scalar_fork.stderr.exp \
	scalar_thr_exit.vgtest \
	scalar_thr_exit.stderr.exp \
	scalar_abort2.vgtest \
	scalar_abort2.stderr.exp \
	scalar_pdfork.vgtest \
	scalar_pdfork.stderr.exp \
	scalar_vfork.vgtest \
	scalar_vfork.stderr.exp \
	stat.vgtest \
	stat.stderr.exp \
		stat.stderr.exp-x86 \
	file_locking_wait6.vgtest \
	file_locking_wait6.stderr.exp \
	utimens.vgtest \
	utimens.stderr.exp \
	access.vgtest \
	access.stderr.exp

check_PROGRAMS = \
	statvfs pdfork_pdkill getfsstat inlinfo inlinfo_nested.so extattr \
	sigwait chflags get_set_login revoke scalar capsicum getfh \
	linkat scalar_fork scalar_thr_exit scalar_abort2 scalar_pdfork \
	scalar_vfork stat file_locking_wait6 utimens access

AM_CFLAGS   += $(AM_FLAG_M3264_PRI)
AM_CXXFLAGS += $(AM_FLAG_M3264_PRI)

inlinfo_SOURCES = inlinfo.c
inlinfo_DEPENDENCIES = inlinfo_nested.so
inlinfo_LDFLAGS = -Wl,-rpath,$(top_builddir)/memcheck/tests/freebsd
inlinfo_LDADD = inlinfo_nested.so
inlinfo_nested_so_SOURCES = inlinfo_nested.c
inlinfo_nested_so_CFLAGS = $(AM_CFLAGS) -fPIC @FLAG_W_NO_UNINITIALIZED@
inlinfo_nested_so_LDFLAGS = -Wl,-rpath,$(top_builddir)/memcheck/tests/freebsd -shared -fPIC

scalar_CFLAGS = -g
