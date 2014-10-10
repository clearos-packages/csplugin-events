AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = csplugin-sysmon.conf csplugin-sysmon.h sysmon-alert.h \
	sysmon-alert-source.h sysmon-conf.h sysmon-db.h sysmon-socket.h \
	sysmon-syslog.h sysmonctl.h

AM_CFLAGS = ${CFLAGS}
AM_CXXFLAGS = ${CXXFLAGS}

bin_PROGRAMS = sysmonctl

sysmonctl_SOURCES = sysmonctl.cpp
sysmonctl_CXXFLAGS = ${AM_CXXFLAGS}
sysmonctl_LDADD = -lclearsync -lcsplugin-sysmon

lib_LTLIBRARIES = libcsplugin-sysmon.la

libcsplugin_sysmon_la_SOURCES = csplugin-sysmon.cpp sysmon-alert.cpp \
				sysmon-alert-source.cpp sysmon-conf.cpp \
				sysmon-db.cpp sysmon-socket.cpp sysmon-syslog.cpp
libcsplugin_sysmon_la_CXXFLAGS = ${AM_CXXFLAGS}

