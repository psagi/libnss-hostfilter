## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = gnits 1.4

EXTRA_DIST = README libnss_hostfilter.map

lib_LTLIBRARIES = libnss_hostfilter.la
libnss_hostfilter_la_SOURCES = hostfilter-host.c
libnss_hostfilter_la_LDFLAGS = -version-info 2 \
	-Wl,--version-script=$(srcdir)/libnss_hostfilter.map
libnss_hostfilter_la_DEPENDENCIES = libnss_hostfilter.map
