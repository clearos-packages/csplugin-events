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
#define _SYSMON_CONF_SYSMON_SOCKET  "/var/lib/csplugin-sysmon/sysmon.socket"
#define _SYSMON_CONF_SYSWATCH_STATE "/var/lib/syswatch/state"
#define _SYSMON_CONF_SYSLOG_SOCKET  "/var/lib/csplugin-sysmon/syslog.socket"

typedef map<uint32_t, string> csAlertIdMap;

class csSysMonAlertPatternExistsException : public csException
{
public:
    explicit csSysMonAlertPatternExistsException()
        : csException(EEXIST, "Alert pattern exists") { }
};

class csSysMonAlertPatternNotFoundException : public csException
{
public:
    explicit csSysMonAlertPatternNotFoundException()
        : csException(ENOENT, "Alert pattern not found") { }
};

class csSysMonAlertSourceConfig
{
public:
    enum csSysMonAlertSourceType
    {
        csAST_NULL,
        csAST_SYSLOG,
        csAST_SYSWATCH,
    };

    csSysMonAlertSourceConfig(csSysMonAlertSourceType type, uint32_t alert_type);
    virtual ~csSysMonAlertSourceConfig();

    csSysMonAlertSourceType GetType(void) { return type; }
    uint32_t GetAlertType(void) { return alert_type; }

protected:
    csSysMonAlertSourceType type;
    uint32_t alert_type;
};

typedef vector<csSysMonAlertSourceConfig *> csAlertSourceConfigVector;
typedef map<int, string> csAlertSourceConfig_syslog_match;

typedef struct
{
    string text;
    csAlertSourceConfig_syslog_match match;
    string pattern;
} csAlertSourceConfig_syslog_pattern;

typedef map<string,
    csAlertSourceConfig_syslog_pattern *> csAlertSourceMap_syslog_pattern;

class csSysMonAlertSourceConfig_syslog : public csSysMonAlertSourceConfig
{
public:
    csSysMonAlertSourceConfig_syslog(uint32_t alert_type);
    virtual ~csSysMonAlertSourceConfig_syslog();

    void SetLocale(const string &locale) { this->locale = locale; }

    void AddText(const string &text);
    void AddMatchVar(int index, const string &name);
    void AddPattern(const string &pattern);

    csAlertSourceMap_syslog_pattern *GetPatterns(void) { return &patterns; }

protected:
    string locale;
    csAlertSourceMap_syslog_pattern patterns;
};

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
    enum csSysMonAlertSourceType
    {
        csAST_NULL,
        csAST_SYSLOG,
        csAST_SYSWATCH,
    };

    csSysMonConf(csPluginSysMon *parent,
        const char *filename, csPluginXmlParser *parser)
        : csConf(filename, parser), parent(parent), max_age_ttl(0),
        sysmon_socket_path(_SYSMON_CONF_SYSMON_SOCKET),
        sqlite_db_filename(_SYSMON_CONF_SQLITE_DB),
        syslog_socket_path(_SYSMON_CONF_SYSLOG_SOCKET),
        syswatch_state_path(_SYSMON_CONF_SYSWATCH_STATE) { };
    virtual ~csSysMonConf();

    virtual void Reload(void);

    time_t GetMaxAgeTTL(void) { return max_age_ttl; }
    const string GetSysMonSocketPath(void) const { return sysmon_socket_path; }
    const string GetSqliteDbFilename(void) const { return sqlite_db_filename; }
    const string GetSyslogSocketPath(void) const { return syslog_socket_path; }
    const string GetSyswatchStatePath(void) const { return syswatch_state_path; }
    uint32_t GetAlertId(const string &type);
    string GetAlertType(uint32_t id);
    void GetAlertTypes(csAlertIdMap &types);
    void GetAlertSourceConfigs(csAlertSourceConfigVector &configs);

protected:
    friend class csPluginXmlParser;

    csPluginSysMon *parent;

    time_t max_age_ttl;
    string sysmon_socket_path;
    string sqlite_db_filename;
    string syslog_socket_path;
    string syswatch_state_path;
    csAlertIdMap alert_types;
    csAlertSourceConfigVector alert_source_config;
};

#endif // _SYSMON_CONF_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
