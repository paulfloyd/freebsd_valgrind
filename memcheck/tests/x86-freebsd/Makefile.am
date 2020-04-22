
include $(top_srcdir)/Makefile.tool-tests.am

dist_noinst_SCRIPTS = filter_stderr

EXTRA_DIST = \
	posif_fadvise.vgtest \
	posif_fallocate.vgtest \
	posix_fadvise.stderr.exp \
	posix_fallocate.stderr.exp

check_PROGRAMS = \
	posix_fadvise posix_fallocate

AM_CFLAGS   += $(AM_FLAG_M3264_PRI)
AM_CXXFLAGS += $(AM_FLAG_M3264_PRI)

posix_fallocate_CFLAGS       = $(AM_CFLAGS) @FLAG_W_NO_UNINITIALIZED@
posix_fadvise_CFLAGS       = $(AM_CFLAGS) @FLAG_W_NO_UNINITIALIZED@
