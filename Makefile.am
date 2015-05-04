AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = csplugin-events.conf csplugin-events.h events-alert.h \
	events-conf.h events-db.h events-socket.h events-syslog.h \
	eventsctl.h

AM_CFLAGS = ${CFLAGS}
AM_CXXFLAGS = ${CXXFLAGS}

lib_LTLIBRARIES = libcsplugin-events.la

libcsplugin_events_la_SOURCES = csplugin-events.cpp events-alert.cpp \
				events-conf.cpp events-db.cpp \
				events-socket.cpp events-syslog.cpp
libcsplugin_events_la_CXXFLAGS = ${AM_CXXFLAGS}

bin_PROGRAMS = eventsctl

eventsctl_SOURCES = eventsctl.cpp
eventsctl_CXXFLAGS = ${AM_CXXFLAGS}
eventsctl_LDADD = -lclearsync libcsplugin-events.la

