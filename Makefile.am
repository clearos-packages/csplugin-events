AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = csplugin-sysmon.conf csplugin-sysmon.h sysmon-alert.h sysmon-conf.h sysmon-db.h sysmon-syslog.h

AM_CFLAGS = ${CFLAGS}
AM_CXXFLAGS = ${CXXFLAGS}

lib_LTLIBRARIES = libcsplugin-sysmon.la

libcsplugin_sysmon_la_SOURCES = csplugin-sysmon.cpp sysmon-alert.cpp sysmon-conf.cpp sysmon-db.cpp sysmon-syslog.cpp
libcsplugin_sysmon_la_CXXFLAGS = ${AM_CXXFLAGS}
