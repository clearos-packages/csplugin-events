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
#define _EVENTS_CONF_SYSLOG_SOCKET  "/var/lib/csplugin-events/syslog.socket"
#define _EVENTS_CONF_SYSINFO_REFRESH 5

#define ISDOT(a)    (a[0] == '.' && (!a[1] || (a[1] == '.' && !a[2])))

typedef map<uint32_t, string> csAlertIdMap;

class csEventsInvalidAlertIdException : public csException
{
public:
    explicit csEventsInvalidAlertIdException()
        : csException(ENOENT, "No such Alert ID") { }
};

class csEventsInvalidAlertTypeException : public csException
{
public:
    explicit csEventsInvalidAlertTypeException()
        : csException(ENOENT, "No such Alert type") { }
};

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

class csEventsIniParseException : public csException
{
public:
    explicit csEventsIniParseException(const char *what)
        : csException(EINVAL, what)
        { };
    virtual ~csEventsIniParseException() throw() { };
};

class csEventsAlertSourceConfig
{
public:
    enum csEventsAlertSourceType
    {
        csAST_NULL,
        csAST_SYSLOG,
        csAST_SYSINFO,
    };

    csEventsAlertSourceConfig(
        csEventsAlertSourceType type, uint32_t alert_type, uint32_t alert_level);
    virtual ~csEventsAlertSourceConfig();

    csEventsAlertSourceType GetType(void) { return type; }
    uint32_t GetAlertType(void) { return alert_type; }
    uint32_t GetAlertLevel(void) { return alert_level; }

    void SetLocale(const string &locale) { this->locale = locale; }
    void SetAutoResolve(bool enable = true) { auto_resolve = enable; }
    bool IsAutoResolving(void) { return auto_resolve; }

protected:
    csEventsAlertSourceType type;
    uint32_t alert_type;
    uint32_t alert_level;
    string locale;
    bool auto_resolve;
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

    void AddText(const string &text);
    void AddMatchVar(int index, const string &name);
    void AddPattern(const string &pattern);

    csAlertSourceMap_syslog_pattern *GetPatterns(void) { return &patterns; }

    void Exclude(bool exclude = false) { this->exclude = exclude; };
    bool IsExcluded(void) { return exclude; };

protected:
    bool exclude;
    csAlertSourceMap_syslog_pattern patterns;
};

typedef map<string, string> csAlertSourceMap_sysinfo_text;

class csEventsAlertSourceConfig_sysinfo : public csEventsAlertSourceConfig
{
public:
    enum csEventsAlertSource_sysinfo_key
    {
        csSIK_NULL,
        // Load averages
        csSIK_LOAD_1M,
        csSIK_LOAD_5M,
        csSIK_LOAD_15M,
        // Swap usage (percentage)
        csSIK_SWAP_USAGE,
        // Volume usage (percentage)
        csSIK_VOL_USAGE,
    };

    csEventsAlertSourceConfig_sysinfo(uint32_t alert_type, uint32_t alert_level);

    void AddText(const string &locale, const string &text);
    csAlertSourceMap_sysinfo_text *GetText(void) { return &text; }

    void SetKey(const string &key);
    void SetThreshold(float threshold);
    void SetDuration(unsigned int duration);
    void SetPath(const string &path);

    csEventsAlertSource_sysinfo_key GetKey(void) { return key; }
    float GetThreshold(void) { return threshold; }
    unsigned int GetDuration(void) { return duration; }
    string GetPath(void) { return path; }

protected:
    csEventsAlertSource_sysinfo_key key;
    float threshold;
    unsigned int duration;
    csAlertSourceMap_sysinfo_text text;
    string path;
};

class csEventsConf;
class csPluginXmlParser : public csXmlParser
{
public:
    virtual void ParseElementOpen(csXmlTag *tag);
    virtual void ParseElementClose(csXmlTag *tag);
};

class csAlertsXmlParser : public csXmlParser
{
public:
    virtual void ParseElementOpen(csXmlTag *tag);
    virtual void ParseElementClose(csXmlTag *tag);
};


class csPluginEvents;
class csEventsConf : public csConf
{
public:
    csEventsConf(csPluginEvents *parent,
        const char *filename, csPluginXmlParser *parser);
    virtual ~csEventsConf();

    virtual void Reload(void);

    bool InitDb(void) { return initdb; }
    time_t GetMaxAgeTTL(void) { return max_age_ttl; }
    bool IsEnabled(void) { return enable_status; }
    const string GetExternConfig(void) const { return extern_config; }
    const string GetAlertConfig(void) const { return alert_config; }
    const string GetEventsSocketPath(void) const { return events_socket_path; }
    const string GetSqliteDbFilename(void) const { return sqlite_db_filename; }
    const string GetSyslogSocketPath(void) const { return syslog_socket_path; }
    const time_t GetSysinfoRefresh(void) const { return sysinfo_refresh; }
    uint32_t GetAlertId(const string &type);
    string GetAlertType(uint32_t id);
    uint32_t GetAlertLevel(const string &level);
    void GetAlertTypes(csAlertIdMap &types);
    void MergeRegisteredAlertTypes(csAlertIdMap &types);
    void GetAlertSourceConfigs(csAlertSourceConfigVector &configs);

protected:
    friend class csPluginXmlParser;
    friend class csAlertsXmlParser;

    csPluginEvents *parent;
    csAlertsXmlParser *alerts_parser;

    bool initdb;
    time_t max_age_ttl;
    bool enable_status;
    string extern_config;
    string alert_config;
    string events_socket_path;
    string sqlite_db_filename;
    string syslog_socket_path;
    time_t sysinfo_refresh;
    csAlertIdMap alert_types;
    csAlertSourceConfigVector alert_source_config;
};

#endif // _EVENTS_CONF_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
