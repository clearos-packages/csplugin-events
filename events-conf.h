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

#ifndef _EVENTS_CONF_H
#define _EVENTS_CONF_H

#define _EVENTS_CONF_SQLITE_DB      "/var/lib/csplugin-events/events.db"
#define _EVENTS_CONF_EVENTS_SOCKET  "/var/lib/csplugin-events/events.socket"
#define _EVENTS_CONF_SYSWATCH_STATE "/var/lib/syswatch/state"
#define _EVENTS_CONF_SYSLOG_SOCKET  "/var/lib/csplugin-events/syslog.socket"

typedef map<uint32_t, string> csAlertIdMap;

class csEventsAlertPatternExistsException : public csException
{
public:
    explicit csEventsAlertPatternExistsException()
        : csException(EEXIST, "Alert pattern exists") { }
};

class csEventsAlertPatternNotFoundException : public csException
{
public:
    explicit csEventsAlertPatternNotFoundException()
        : csException(ENOENT, "Alert pattern not found") { }
};

class csEventsAlertSourceConfig
{
public:
    enum csEventsAlertSourceType
    {
        csAST_NULL,
        csAST_SYSLOG,
        csAST_SYSWATCH,
    };

    csEventsAlertSourceConfig(
        csEventsAlertSourceType type, uint32_t alert_type, uint32_t alert_level);
    virtual ~csEventsAlertSourceConfig();

    csEventsAlertSourceType GetType(void) { return type; }
    uint32_t GetAlertType(void) { return alert_type; }
    uint32_t GetAlertLevel(void) { return alert_level; }

protected:
    csEventsAlertSourceType type;
    uint32_t alert_type;
    uint32_t alert_level;
};

typedef vector<csEventsAlertSourceConfig *> csAlertSourceConfigVector;
typedef map<int, string> csAlertSourceConfig_syslog_match;

typedef struct
{
    string text;
    csAlertSourceConfig_syslog_match match;
    string pattern;
} csAlertSourceConfig_syslog_pattern;

typedef map<string,
    csAlertSourceConfig_syslog_pattern *> csAlertSourceMap_syslog_pattern;

class csEventsAlertSourceConfig_syslog : public csEventsAlertSourceConfig
{
public:
    csEventsAlertSourceConfig_syslog(uint32_t alert_type, uint32_t alert_level);
    virtual ~csEventsAlertSourceConfig_syslog();

    void SetLocale(const string &locale) { this->locale = locale; }

    void AddText(const string &text);
    void AddMatchVar(int index, const string &name);
    void AddPattern(const string &pattern);

    csAlertSourceMap_syslog_pattern *GetPatterns(void) { return &patterns; }

    void Exclude(bool exclude = false) { this->exclude = exclude; };
    bool IsExcluded(void) { return exclude; };

protected:
    string locale;
    bool exclude;
    csAlertSourceMap_syslog_pattern patterns;
};

class csEventsConf;
class csPluginXmlParser : public csXmlParser
{
public:
    virtual void ParseElementOpen(csXmlTag *tag);
    virtual void ParseElementClose(csXmlTag *tag);
};

class csPluginEvents;
class csEventsConf : public csConf
{
public:
    enum csEventsAlertSourceType
    {
        csAST_NULL,
        csAST_SYSLOG,
        csAST_SYSWATCH,
    };

    csEventsConf(csPluginEvents *parent,
        const char *filename, csPluginXmlParser *parser)
        : csConf(filename, parser), parent(parent),
        initdb(false), max_age_ttl(0),
        events_socket_path(_EVENTS_CONF_EVENTS_SOCKET),
        sqlite_db_filename(_EVENTS_CONF_SQLITE_DB),
        syslog_socket_path(_EVENTS_CONF_SYSLOG_SOCKET),
        syswatch_state_path(_EVENTS_CONF_SYSWATCH_STATE) { };
    virtual ~csEventsConf();

    virtual void Reload(void);

    bool InitDb(void) { return initdb; }
    time_t GetMaxAgeTTL(void) { return max_age_ttl; }
    const string GetExternConfig(void) const { return extern_config; }
    const string GetAlertConfig(void) const { return alert_config; }
    const string GetEventsSocketPath(void) const { return events_socket_path; }
    const string GetSqliteDbFilename(void) const { return sqlite_db_filename; }
    const string GetSyslogSocketPath(void) const { return syslog_socket_path; }
    const string GetSyswatchStatePath(void) const { return syswatch_state_path; }
    uint32_t GetAlertId(const string &type);
    string GetAlertType(uint32_t id);
    void GetAlertTypes(csAlertIdMap &types);
    void GetAlertSourceConfigs(csAlertSourceConfigVector &configs);

protected:
    friend class csPluginXmlParser;

    csPluginEvents *parent;

    bool initdb;
    time_t max_age_ttl;
    string extern_config;
    string alert_config;
    string events_socket_path;
    string sqlite_db_filename;
    string syslog_socket_path;
    string syswatch_state_path;
    csAlertIdMap alert_types;
    csAlertSourceConfigVector alert_source_config;
};

#endif // _EVENTS_CONF_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
