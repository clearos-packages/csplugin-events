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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <clearsync/csplugin.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include <openssl/sha.h>

#include "events-conf.h"
#include "events-alert.h"

#include "inih/cpp/INIReader.h"

csEventsAlertSourceConfig::csEventsAlertSourceConfig(
    csEventsAlertSourceType type, uint32_t alert_type, uint32_t alert_level)
    : type(type), alert_type(alert_type), alert_level(alert_level)
{
}

csEventsAlertSourceConfig::~csEventsAlertSourceConfig()
{
}

csEventsAlertSourceConfig_syslog::csEventsAlertSourceConfig_syslog(
    uint32_t alert_type, uint32_t alert_level
) : csEventsAlertSourceConfig(csAST_SYSLOG, alert_type, alert_level),
    locale("en"), exclude(false)
{
}

csEventsAlertSourceConfig_syslog::~csEventsAlertSourceConfig_syslog()
{
    csAlertSourceMap_syslog_pattern::iterator i;
    for (i = patterns.begin(); i != patterns.end(); i++)
        delete i->second;
}

void csEventsAlertSourceConfig_syslog::AddText(const string &text)
{
    csAlertSourceConfig_syslog_pattern *p;
    csAlertSourceMap_syslog_pattern::iterator i = patterns.find(locale);
    if (i == patterns.end()) {
        p = new csAlertSourceConfig_syslog_pattern;
        patterns[locale] = p;
    }
    else
        p = i->second;

    p->text = text;
}

void csEventsAlertSourceConfig_syslog::AddMatchVar(int index, const string &name)
{
    csAlertSourceConfig_syslog_pattern *p;
    csAlertSourceMap_syslog_pattern::iterator i = patterns.find(locale);
    if (i == patterns.end()) {
        p = new csAlertSourceConfig_syslog_pattern;
        patterns[locale] = p;
    }
    else
        p = i->second;

    p->match[index] = "$" + name;
}

void csEventsAlertSourceConfig_syslog::AddPattern(const string &pattern)
{
    csAlertSourceConfig_syslog_pattern *p;
    csAlertSourceMap_syslog_pattern::iterator i = patterns.find(locale);
    if (i == patterns.end()) {
        p = new csAlertSourceConfig_syslog_pattern;
        patterns[locale] = p;
    }
    else
        p = i->second;

    p->pattern = pattern;
}

void csEventsConf::Reload(void)
{
    csConf::Reload();
    parser->Parse();

    // Read and parse external (webconfig) configuration.
    struct stat extern_config_stat;
    if (stat(extern_config.c_str(), &extern_config_stat)  == 0) {
        INIReader reader(extern_config.c_str());

        if (reader.ParseError() < 0)
            throw csException(errno, "Error parsing external configuration");

        enable_status = reader.GetBoolean("", "status", "true");
        csLog::Log(csLog::Debug,
            "%s: %s = %ld", __PRETTY_FUNCTION__, "status", enable_status);
        max_age_ttl = (time_t)reader.GetInteger("", "autopurge", 60 * 86400);
        csLog::Log(csLog::Debug,
            "%s: %s = %ld", __PRETTY_FUNCTION__, "autopurge", max_age_ttl);
    }

    // Load external alert configuration files
    DIR *dh = opendir(alert_config.c_str());
    if (dh == NULL) {
        csLog::Log(csLog::Warning,
            "Error opening external alert directory: %s: %s",
            alert_config.c_str(), strerror(errno));
        return;
    }

    struct dirent *entry;
    struct stat conf_stat;

    while ((entry = readdir(dh)) != NULL) {
        if (ISDOT(entry->d_name)) continue;
        string path = alert_config.c_str();
        path.append("/");
        path.append(entry->d_name);
        if (stat(path.c_str(), &conf_stat) != 0) {
            csLog::Log(csLog::Warning,
                "Can't stat config file: %s: %s\n", path.c_str(), strerror(errno));
            continue;
        }
        if (S_ISDIR(conf_stat.st_mode)) continue;

        alerts_parser->Parse(path.c_str());
    }

    closedir(dh);
}

void csPluginXmlParser::ParseElementOpen(csXmlTag *tag)
{
    csEventsConf *_conf = static_cast<csEventsConf *>(conf);

    csLog::Log(csLog::Debug, "%s: %s", __PRETTY_FUNCTION__, tag->GetName().c_str());
}

void csPluginXmlParser::ParseElementClose(csXmlTag *tag)
{
    csEventsConf *_conf = static_cast<csEventsConf *>(conf);

    csLog::Log(csLog::Debug, "%s: %s", __PRETTY_FUNCTION__, tag->GetName().c_str());

    if ((*tag) == "start-up") {
        if (!stack.size() || (*stack.back()) != "plugin")
            ParseError("unexpected tag: " + tag->GetName());
        if (tag->ParamExists("initdb") && tag->GetParamValue("initdb") == "true") {
            _conf->initdb = true;
        }
    }
    else if ((*tag) == "auto-purge-ttl") {
        if (!stack.size() || (*stack.back()) != "plugin")
            ParseError("unexpected tag: " + tag->GetName());
        if (!tag->ParamExists("max-age"))
            ParseError("max-age parameter missing");

        _conf->max_age_ttl = (time_t)atoi(tag->GetParamValue("max-age").c_str());
    }
    else if ((*tag) == "extern-config") {
        if (!stack.size() || (*stack.back()) != "plugin")
            ParseError("unexpected tag: " + tag->GetName());
        if (!tag->ParamExists("path"))
            ParseError("path parameter missing");
        _conf->extern_config = tag->GetParamValue("path");
    }
    else if ((*tag) == "alert-config") {
        if (!stack.size() || (*stack.back()) != "plugin")
            ParseError("unexpected tag: " + tag->GetName());
        if (!tag->ParamExists("path"))
            ParseError("path parameter missing");
        _conf->alert_config = tag->GetParamValue("path");
    }
    else if ((*tag) == "eventsctl") {
        if (!stack.size() || (*stack.back()) != "plugin")
            ParseError("unexpected tag: " + tag->GetName());
        if (!tag->ParamExists("socket"))
            ParseError("socket parameter missing");
        _conf->events_socket_path = tag->GetParamValue("socket");
    }
    else if ((*tag) == "db") {
        if (!stack.size() || (*stack.back()) != "plugin")
            ParseError("unexpected tag: " + tag->GetName());
        if (!tag->ParamExists("type"))
            ParseError("type parameter missing");
        if (tag->GetParamValue("type") == "sqlite") {
            if (!tag->ParamExists("db_filename"))
                ParseError("db_filename parameter missing");
            _conf->sqlite_db_filename = tag->GetParamValue("db_filename");
        }
        else ParseError("invalid type parameter");
    }
    else if ((*tag) == "source") {
        if (!stack.size() || (*stack.back()) != "plugin")
            ParseError("unexpected tag: " + tag->GetName());
        if (!tag->ParamExists("type"))
            ParseError("type parameter missing");
        if (tag->GetParamValue("type") == "syslog") {
            if (!tag->ParamExists("socket"))
                ParseError("socket parameter missing");
            _conf->syslog_socket_path = tag->GetParamValue("socket");
        }
        else if (tag->GetParamValue("type") == "syswatch") {
            if (!tag->ParamExists("state"))
                ParseError("state parameter missing");
            _conf->syswatch_state_path = tag->GetParamValue("state");
        }
        else ParseError("invalid type parameter");
    }
    else if ((*tag) == "types") {
        if (!stack.size() || (*stack.back()) != "plugin")
            ParseError("unexpected tag: " + tag->GetName());
    }
    else if ((*tag) == "type") {
        if (!stack.size() || (*stack.back()) != "types")
            ParseError("unexpected tag: " + tag->GetName());
        if (!tag->ParamExists("id"))
            ParseError("id parameter missing");
        if (!tag->ParamExists("type"))
            ParseError("type parameter missing");

        uint32_t id = (uint32_t)atoi(tag->GetParamValue("id").c_str());
        if (id == 0)
            ParseError("invalid id value (can not be 0)");

        bool exists = false;
        try {
            _conf->GetAlertType(id);
            exists = true;
        }
        catch (csException &e) { }
        if (exists)
            ParseError("alert id already defined");

        string type;
        try {
            type = _conf->GetAlertId(tag->GetParamValue("type"));
        }
        catch (csException &e) { }
        if (type.length() != 0)
            ParseError("alert type already defined");

        _conf->alert_types[id] = tag->GetParamValue("type");
    }
}

void csAlertsXmlParser::ParseElementOpen(csXmlTag *tag)
{
    csEventsConf *_conf = static_cast<csEventsConf *>(conf);

    csLog::Log(csLog::Debug, "%s: %s", __PRETTY_FUNCTION__, tag->GetName().c_str());

    if ((*tag) == "alert") {
        if (!stack.size() || (*stack.back()) != "alerts")
            ParseError("unexpected tag: " + tag->GetName());
        if (!tag->ParamExists("type"))
            ParseError("type parameter missing");
        if (!tag->ParamExists("level"))
            ParseError("level parameter missing");
        if (!tag->ParamExists("source"))
            ParseError("source parameter missing");

        uint32_t id = 0;
        try {
            id = _conf->GetAlertId(tag->GetParamValue("type"));
        }
        catch (csException &e) { }
        if (id == 0)
            ParseError("invalid type parameter");

        uint32_t level = 0;
        try {
            level = _conf->GetAlertLevel(tag->GetParamValue("level"));
        } catch (csException &e) { }
        if (level == 0)
            ParseError("invalid level parameter");

        if (tag->GetParamValue("source") == "syslog") {
            csEventsAlertSourceConfig_syslog *syslog_config;
            syslog_config = new csEventsAlertSourceConfig_syslog(id, level);
            if (tag->ParamExists("exclude") &&
                tag->GetParamValue("exclude") == "true")
                syslog_config->Exclude(true);
            tag->SetData(syslog_config);

        }
        else
            ParseError("invalid source parameter");
    }
    else if ((*tag) == "locale") {
        if (!stack.size() || (*stack.back()) != "alert")
            ParseError("unexpected tag: " + tag->GetName());
        if (!tag->ParamExists("lang"))
            ParseError("lang parameter missing");

        csEventsAlertSourceConfig *asc;
        asc = reinterpret_cast<csEventsAlertSourceConfig *>(stack.back()->GetData());
        if (asc == NULL) ParseError("missing configuration data");
        if (asc->GetType() != csEventsAlertSourceConfig::csAST_SYSLOG)
            ParseError("wrong type of configuration data");
        csEventsAlertSourceConfig_syslog *ascs;
        ascs = reinterpret_cast<csEventsAlertSourceConfig_syslog *>(stack.back()->GetData());
        ascs->SetLocale(tag->GetParamValue("lang"));
        tag->SetData(asc);
    }
}

void csAlertsXmlParser::ParseElementClose(csXmlTag *tag)
{
    csEventsConf *_conf = static_cast<csEventsConf *>(conf);

    csLog::Log(csLog::Debug, "%s: %s", __PRETTY_FUNCTION__, tag->GetName().c_str());

    if ((*tag) == "text") {
        if (!stack.size() || (*stack.back()) != "locale")
            ParseError("unexpected tag: " + tag->GetName());

        string text = tag->GetText();
        if (text.length() == 0) ParseError("alert text missing");

        csEventsAlertSourceConfig *asc;
        asc = reinterpret_cast<csEventsAlertSourceConfig *>(stack.back()->GetData());
        if (asc == NULL) ParseError("missing configuration data");
        if (asc->GetType() != csEventsAlertSourceConfig::csAST_SYSLOG)
            ParseError("wrong type of configuration data");

        csEventsAlertSourceConfig_syslog *ascs;
        ascs = reinterpret_cast<csEventsAlertSourceConfig_syslog *>(stack.back()->GetData());

        ascs->AddText(text);
    }
    else if ((*tag) == "match") {
        if (!stack.size() || (*stack.back()) != "locale")
            ParseError("unexpected tag: " + tag->GetName());
        if (!tag->ParamExists("index"))
            ParseError("index parameter missing");
        if (!tag->ParamExists("name"))
            ParseError("name parameter missing");

        csEventsAlertSourceConfig *asc;
        asc = reinterpret_cast<csEventsAlertSourceConfig *>(stack.back()->GetData());
        if (asc == NULL) ParseError("missing configuration data");
        if (asc->GetType() != csEventsAlertSourceConfig::csAST_SYSLOG)
            ParseError("wrong type of configuration data");

        csEventsAlertSourceConfig_syslog *ascs;
        ascs = reinterpret_cast<csEventsAlertSourceConfig_syslog *>(stack.back()->GetData());

        ascs->AddMatchVar(
            atoi(tag->GetParamValue("index").c_str()),
            tag->GetParamValue("name"));
    }
    else if ((*tag) == "pattern") {
        if (!stack.size() || (*stack.back()) != "locale")
            ParseError("unexpected tag: " + tag->GetName());

        string text = tag->GetText();
        if (text.length() == 0) ParseError("pattern text missing");

        csEventsAlertSourceConfig *asc;
        asc = reinterpret_cast<csEventsAlertSourceConfig *>(stack.back()->GetData());
        if (asc == NULL) ParseError("missing configuration data");
        if (asc->GetType() != csEventsAlertSourceConfig::csAST_SYSLOG)
            ParseError("wrong type of configuration data");

        csEventsAlertSourceConfig_syslog *ascs;
        ascs = reinterpret_cast<csEventsAlertSourceConfig_syslog *>(stack.back()->GetData());

        ascs->AddPattern(text);
    }
    else if ((*tag) == "alert") {
        if (!stack.size() || (*stack.back()) != "alerts")
            ParseError("unexpected tag: " + tag->GetName());

        csEventsAlertSourceConfig *asc;
        asc = reinterpret_cast<csEventsAlertSourceConfig *>(tag->GetData());
        if (asc == NULL) ParseError("missing configuration data");
        _conf->alert_source_config.push_back(asc);
    }
}

csEventsConf::csEventsConf(csPluginEvents *parent,
        const char *filename, csPluginXmlParser *parser)
        : csConf(filename, parser), parent(parent), alerts_parser(NULL),
        initdb(false), max_age_ttl(0), enable_status(true),
        events_socket_path(_EVENTS_CONF_EVENTS_SOCKET),
        sqlite_db_filename(_EVENTS_CONF_SQLITE_DB),
        syslog_socket_path(_EVENTS_CONF_SYSLOG_SOCKET),
        syswatch_state_path(_EVENTS_CONF_SYSWATCH_STATE)
{
    alerts_parser = new csAlertsXmlParser();
    alerts_parser->SetConf(this);
}

csEventsConf::~csEventsConf()
{
    csAlertSourceConfigVector::iterator i;
    for (i = alert_source_config.begin(); i != alert_source_config.end(); i++)
        delete (*i);
    if (alerts_parser != NULL) delete alerts_parser;
}

uint32_t csEventsConf::GetAlertId(const string &type)
{
    csAlertIdMap::iterator i = alert_types.begin();
    for ( ; i != alert_types.end(); i++) {
        if (i->second != type) continue;
        break;
    }
    if (i == alert_types.end())
        throw csException(ENOENT, "No such Alert type");
    return i->first;
}

string csEventsConf::GetAlertType(uint32_t id)
{
    csAlertIdMap::iterator i = alert_types.find(id);
    if (i == alert_types.end())
        throw csException(ENOENT, "No such Alert ID");
    return i->second;
}

uint32_t csEventsConf::GetAlertLevel(const string &level)
{
    uint32_t level_id = 0;

    if (strncasecmp(level.c_str(), "NORM", 4) == 0)
        level_id = csEventsAlert::csAF_LVL_NORM;
    else if (strncasecmp(level.c_str(), "WARN", 4) == 0)
        level_id = csEventsAlert::csAF_LVL_WARN;
    else if (strncasecmp(level.c_str(), "CRIT", 4) == 0)
        level_id = csEventsAlert::csAF_LVL_CRIT;
    else
        throw csException(EINVAL, "Invalid level");

    return level_id;
}

void csEventsConf::GetAlertTypes(csAlertIdMap &types)
{
    types.clear();
    csAlertIdMap::const_iterator i;
    for (i = alert_types.begin(); i != alert_types.end(); i++)
        types[i->first] = i->second;
}

void csEventsConf::GetAlertSourceConfigs(csAlertSourceConfigVector &configs)
{
    configs.clear();
    csAlertSourceConfigVector::iterator i;
    for (i = alert_source_config.begin(); i != alert_source_config.end(); i++)
        configs.push_back((*i));
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
