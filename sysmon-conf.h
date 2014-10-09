// ClearSync: System Monitor plugin.
// Copyright (C) 2011 ClearFoundation <http://www.clearfoundation.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifndef _SYSMON_CONF_H
#define _SYSMON_CONF_H

#define _SYSMON_CONF_SQLITE_DB      "/var/lib/csplugin-sysmon/sysmon.db"
#define _SYSMON_CONF_SYSWATCH_STATE "/var/lib/syswatch/state"
#define _SYSMON_CONF_SYSLOG_SOCKET  "/var/lib/csplugin-sysmon/syslog.socket"

typedef map<uint32_t, string> csAlertIdMap;
//typedef map<string, vector<string> > csAlertPatternMap;
//typedef map<uint32_t, csAlertPatternMap> csAlertSyslogMap;

class csSysMonConf;
class csPluginXmlParser : public csXmlParser
{
public:
    virtual void ParseElementOpen(csXmlTag *tag);
    virtual void ParseElementClose(csXmlTag *tag);
};

class csPluginSysMon;
class csSysMonConf : public csConf
{
public:
    csSysMonConf(csPluginSysMon *parent,
        const char *filename, csPluginXmlParser *parser)
        : csConf(filename, parser), parent(parent),
        max_age_ttl(0), sqlite_db_filename(_SYSMON_CONF_SQLITE_DB),
        syslog_socket_path(_SYSMON_CONF_SYSLOG_SOCKET),
        syswatch_state_path(_SYSMON_CONF_SYSWATCH_STATE) { };

    virtual void Reload(void);

    time_t GetMaxAgeTTL(void) { return max_age_ttl; }
    const string GetSqliteDbFilename(void) const { return sqlite_db_filename; }
    const string GetSyslogSocketPath(void) const { return syslog_socket_path; }
    const string GetSyswatchStatePath(void) const { return syswatch_state_path; }
    uint32_t GetAlertId(const string &type);
    string GetAlertType(uint32_t id);

protected:
    friend class csPluginXmlParser;

    csPluginSysMon *parent;

    time_t max_age_ttl;
    string sqlite_db_filename;
    string syslog_socket_path;
    string syswatch_state_path;
    csAlertIdMap alert_types;
};

#endif // _SYSMON_CONF_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
