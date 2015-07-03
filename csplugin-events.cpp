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

#include <sstream>
#include <iomanip>

#include <unistd.h>
#include <fcntl.h>
#include <linux/un.h>
#include <sqlite3.h>

#include <sys/sysinfo.h>
#include <sys/statvfs.h>

#include <openssl/sha.h>

#include "events-conf.h"
#include "events-alert.h"
#include "events-db.h"
#include "events-socket.h"
#include "events-syslog.h"
#include "csplugin-events.h"

csPluginEvents::csPluginEvents(const string &name,
    csEventClient *parent, size_t stack_size)
    : csPlugin(name, parent, stack_size),
    events_conf(NULL), events_db(NULL), events_syslog(NULL),
    events_socket_server(NULL)
{
    ::csGetLocale(locale);
    size_t uscore_delim = locale.find_first_of('_');
    if (uscore_delim != string::npos) {
        string temp;
        ::csGetLocale(temp);
        temp = locale.substr(0, uscore_delim);
        locale = temp;
    }

    events_sysinfo_keys.push_back("$threshold");
    events_sysinfo_keys.push_back("$path");
    events_sysinfo_keys.push_back("$swap_used");
    events_sysinfo_keys.push_back("$vol_used");

    csLog::Log(csLog::Debug, "%s: Initialized (locale: %s)",
        name.c_str(), locale.c_str());
}

csPluginEvents::~csPluginEvents()
{
    Join();

    if (events_conf != NULL) delete events_conf;
    if (events_db != NULL) delete events_db;
    if (events_syslog != NULL) delete events_syslog;
    if (events_socket_server != NULL) delete events_socket_server;
    for (csPluginEventsClientMap::iterator i = events_socket_client.begin();
        i != events_socket_client.end(); i++) delete i->second;
    for (csEventsSyslogRegExVector::iterator i = events_syslog_rx.begin();
        i != events_syslog_rx.end(); i++) {
        if ((*i)->rx) delete (*i)->rx;
        if ((*i)->rx_en) delete (*i)->rx_en;
        delete (*i);
    }
    for (csEventsSysinfoConfigMap::iterator i = events_sysinfo.begin();
        i != events_sysinfo.end(); i++) {
        for (vector<csEventsSysinfoConfig *>::iterator j = i->second.begin();
            j != i->second.end(); j++) {
            delete (*j);
        }
    }
}

void csPluginEvents::SetConfigurationFile(const string &conf_filename)
{
    if (events_conf != NULL) delete events_conf;

    csPluginXmlParser *parser = new csPluginXmlParser();
    events_conf = new csEventsConf(this, conf_filename.c_str(), parser);
    parser->SetConf(dynamic_cast<csConf *>(events_conf));
    events_conf->Reload();

    if (events_db != NULL) delete events_db;
    events_db = new csEventsDb_sqlite(events_conf->GetSqliteDbFilename());
    if (events_syslog != NULL) delete events_syslog;
    events_syslog = new csEventsSyslog(events_conf->GetSyslogSocketPath());

    try {
        if (events_socket_server != NULL) delete events_socket_server;
        events_socket_server = new csEventsSocketServer(
            events_conf->GetEventsSocketPath());
    } catch (csEventsSocketException &e) {
        csLog::Log(csLog::Error,
            "%s: %s: %s", name.c_str(), e.estring.c_str(), e.what());
    }

    csAlertSourceConfigVector alert_sources;
    events_conf->GetAlertSourceConfigs(alert_sources);

    for (csAlertSourceConfigVector::iterator i = alert_sources.begin();
        i != alert_sources.end(); i++) {

        if ((*i)->GetType() == csEventsAlertSourceConfig::csAST_SYSLOG) {
            LoadAlertConfig(
                reinterpret_cast<csEventsAlertSourceConfig_syslog *>((*i)));
        }
        else if ((*i)->GetType() == csEventsAlertSourceConfig::csAST_SYSINFO) {
            LoadAlertConfig(
                reinterpret_cast<csEventsAlertSourceConfig_sysinfo *>((*i)));
        }
    }
}

void csPluginEvents::LoadAlertConfig(csEventsAlertSourceConfig_syslog *syslog_config)
{
    csAlertSourceMap_syslog_pattern *patterns;
    patterns = syslog_config->GetPatterns();

    for (csAlertSourceMap_syslog_pattern::iterator j = patterns->begin();
        j != patterns->end(); j++) {

        csEventsSyslogRegEx *entry = NULL;

        try {
            entry = new csEventsSyslogRegEx;
            memset(entry, 0, sizeof(csEventsSyslogRegEx));
            entry->type = syslog_config->GetAlertType();
            entry->level = syslog_config->GetAlertLevel();
            entry->exclude = syslog_config->IsExcluded();

            if (j->first == locale) {
                entry->rx = new csRegEx(
                    j->second->pattern.c_str(),
                    j->second->match.size() + 1
                );
                entry->config = j->second;
            }
            if (j->first == "en") {
                entry->rx_en = new csRegEx(
                    j->second->pattern.c_str(),
                    j->second->match.size() + 1
                );
                entry->config_en = j->second;
            }

            if (entry->rx == NULL && entry->rx_en == NULL) {
                delete entry;
                continue;
            }
        }
        catch (csException &e) {
            csLog::Log(csLog::Error,
                "%s: Regular expression compilation failed: %s",
                    name.c_str(), e.what());
            if (entry != NULL) delete entry;
            entry = NULL;
        }

        if (entry != NULL)
            events_syslog_rx.push_back(entry);
    }
}

void csPluginEvents::LoadAlertConfig(csEventsAlertSourceConfig_sysinfo *sysinfo_config)
{
    csEventsSysinfoConfig *config = new csEventsSysinfoConfig;
    config->type = sysinfo_config->GetAlertType();
    config->level = sysinfo_config->GetAlertLevel();
    config->auto_resolve = sysinfo_config->IsAutoResolving();
    config->threshold = sysinfo_config->GetThreshold();
    config->duration = sysinfo_config->GetDuration();
    config->trigger_start_time = 0;
    config->trigger_active = false;
    config->path = sysinfo_config->GetPath();
    
    csAlertSourceMap_sysinfo_text *text = sysinfo_config->GetText();
    for (csAlertSourceMap_sysinfo_text::iterator i = text->begin();
        i != text->end(); i++) {
        map<string, string>::iterator j = config->text.find(i->first);
        if (j != config->text.end()) continue;
        config->text[i->first] = i->second;
    }

    events_sysinfo[sysinfo_config->GetKey()].push_back(config);
}

void *csPluginEvents::Entry(void)
{
    int rc;
    fd_set fds_read;
    struct timeval tv;

    csLog::Log(csLog::Debug, "%s: Started", name.c_str());

    try {
        events_db->Open();
        if (events_conf->InitDb()) events_db->Drop();
        events_db->Create();

        RefreshAlertTypes();
        RefreshLevelOverrides();
    }
    catch (csEventsDbException &e) {
        csLog::Log(csLog::Error,
            "%s: Database exception: %s", name.c_str(), e.estring.c_str());
    }

    csTimer *purge_timer = new csTimer(_CSPLUGIN_EVENTS_PURGE_TIMER_ID,
        _CSPLUGIN_EVENTS_PURGE_TIMER, _CSPLUGIN_EVENTS_PURGE_TIMER, this
    );
    purge_timer->Start();

    csTimer *sysinfo_timer = new csTimer(_CSPLUGIN_EVENTS_SYSINFO_TIMER_ID,
        events_conf->GetSysinfoRefresh(), events_conf->GetSysinfoRefresh(), this
    );
    sysinfo_timer->Start();

    for (bool run = true; run; ) {

        int max_fd = events_socket_server->GetDescriptor();

        FD_ZERO(&fds_read);
        FD_SET(max_fd, &fds_read);

        for (csPluginEventsClientMap::iterator i = events_socket_client.begin();
            i != events_socket_client.end(); i++) {
            FD_SET(i->first, &fds_read);
            if (i->first > max_fd) max_fd = i->first;
        }

        FD_SET(events_syslog->GetDescriptor(), &fds_read);
        if (events_syslog->GetDescriptor() > max_fd)
            max_fd = events_syslog->GetDescriptor();

        tv.tv_sec = 1; tv.tv_usec = 0;

        rc = select(max_fd + 1, &fds_read, NULL, NULL, &tv);

        if (rc > 0) ProcessEventSelect(fds_read);

        csTimer *timer;
        csEvent *event = EventPop();

        if (event != NULL) {
            switch (event->GetId()) {
            case csEVENT_QUIT:
                purge_timer->Stop();
                sysinfo_timer->Stop();
                csLog::Log(csLog::Debug, "%s: Terminated.", name.c_str());
                run = false;
                break;

            case csEVENT_TIMER:
                timer = static_cast<csEventTimer *>(event)->GetTimer();

                if (timer->GetId() == _CSPLUGIN_EVENTS_PURGE_TIMER_ID &&
                    events_conf->GetMaxAgeTTL()) {
                    events_db->PurgeAlerts(csEventsAlert(),
                        time(NULL) - events_conf->GetMaxAgeTTL());
                } else if (timer->GetId() == _CSPLUGIN_EVENTS_SYSINFO_TIMER_ID)
                    ProcessSysinfoRefresh();
                break;
            }

            EventDestroy(event);
        }

        // Select error?
        if (rc == -1) {
            csLog::Log(csLog::Error, "%s: select: %s", name.c_str(), strerror(rc));
            break;
        }
    }

    delete purge_timer;
    delete sysinfo_timer;

    return NULL;
}

void csPluginEvents::ProcessEventSelect(fd_set &fds)
{
    vector<string> syslog_messages;
    csPluginEventsClientMap::iterator sci;

    try {
        if (FD_ISSET(events_syslog->GetDescriptor(), &fds)) {

            events_syslog->Read(syslog_messages);

            if (!events_conf->IsEnabled()) syslog_messages.clear();

            for (vector<string>::iterator i = syslog_messages.begin();
                i != syslog_messages.end(); i++) {
                for (csEventsSyslogRegExVector::iterator j = events_syslog_rx.begin();
                    j != events_syslog_rx.end(); j++) {

                    csRegEx *rx = (*j)->rx;
                    csAlertSourceConfig_syslog_pattern *rx_config = (*j)->config;
                    if (rx == NULL) {
                        rx = (*j)->rx_en;
                        rx_config = (*j)->config_en;
                    }
                    if (rx == NULL) continue;
                    if (rx->Execute((*i).c_str()) != 0) continue;
                    if ((*j)->exclude) break;

                    string text;
                    SyslogTextSubstitute(text, rx, rx_config);
                    if (text.length() == 0) continue;

                    csLog::Log(csLog::Debug, "%s: %s", name.c_str(), (*i).c_str());
                    csLog::Log(csLog::Debug, "%s: %s", name.c_str(), text.c_str());

                    csEventsAlert alert;
                    alert.SetType((*j)->type);
                    alert.SetFlag((*j)->level);
                    if ((*j)->auto_resolve)
                        alert.SetFlag(csEventsAlert::csAF_FLG_AUTO_RESOLVE);
                    alert.SetDescription(text);
                    alert.SetUUID(text);
                    alert.SetUser();
                    alert.SetOrigin("internal-syslog");
                    alert.SetBasename("csplugin-events");

                    InsertAlert(alert);

                    break;
                }
            }
        }

        for (csPluginEventsClientMap::iterator i = events_socket_client.begin();
            i != events_socket_client.end(); i++) {
            if (FD_ISSET(i->first, &fds)) ProcessClientRequest(i->second);
        }

        if (FD_ISSET(events_socket_server->GetDescriptor(), &fds)) {

            csEventsSocketClient *client = events_socket_server->Accept();

            if (client != NULL) {
                events_socket_client[client->GetDescriptor()] = client;
                csLog::Log(csLog::Debug, "%s: Accepted new client connection",
                    name.c_str());
            }
       }
    }
    catch (csEventsSocketHangupException &e) {
        csLog::Log(csLog::Warning, "%s: Socket hang-up: %d",
            name.c_str(), e.GetDescriptor());
        sci = events_socket_client.find(e.GetDescriptor());
        if (sci == events_socket_client.end()) {
            csLog::Log(csLog::Error, "%s: Socket hang-up on unknown descriptor: %d",
                name.c_str(), e.GetDescriptor());
        }
        else {
            delete sci->second;
            events_socket_client.erase(sci);
        }
    }
    catch (csEventsSocketTimeoutException &e) {
        csLog::Log(csLog::Error, "%s: Socket time-out: %d",
            name.c_str(), e.GetDescriptor());
        sci = events_socket_client.find(e.GetDescriptor());
        if (sci == events_socket_client.end()) {
            csLog::Log(csLog::Error, "%s: Socket time-out on unknown descriptor: %d",
                name.c_str(), e.GetDescriptor());
        }
        else {
            delete sci->second;
            events_socket_client.erase(sci);
        }
    }
    catch (csEventsSocketProtocolException &e) {
        csLog::Log(csLog::Error, "%s: Protocol error: %d: %s",
            name.c_str(), e.GetDescriptor(), e.estring.c_str());
        sci = events_socket_client.find(e.GetDescriptor());
        if (sci == events_socket_client.end()) {
            csLog::Log(csLog::Error, "%s: Protocol error on unknown descriptor: %d",
                name.c_str(), e.GetDescriptor());
        }
        else {
            delete sci->second;
            events_socket_client.erase(sci);
        }
    }
    catch (csEventsSocketException &e) {
        csLog::Log(csLog::Error, "%s: Socket exception: %s: %s",
            name.c_str(), e.estring.c_str(), e.what());
    }
    catch (csEventsDbException &e) {
        csLog::Log(csLog::Error, "%s: Database exception: %s",
            name.c_str(), e.estring.c_str());
    }
    catch (csException &e) {
        csLog::Log(csLog::Error, "%s: Exception: %s",
            name.c_str(), e.estring.c_str());
    }
}

void csPluginEvents::ProcessClientRequest(csEventsSocketClient *client)
{
    csEventsAlert alert;
    string alert_type, alert_basename;
    uint32_t type = 0, flags = csEventsAlert::csAF_NULL;

    if (client->GetProtoVersion() == 0) {
        client->VersionExchange();

        csLog::Log(csLog::Debug, "%s: Client version: 0x%08x",
            name.c_str(), client->GetProtoVersion());

        return;
    }

    switch (client->ReadPacket()) {
    case csSMOC_ALERT_INSERT:
        client->AlertInsert(alert);
        InsertAlert(alert);
        break;
    case csSMOC_ALERT_SELECT:
        client->AlertSelect(events_db);
        break;
    case csSMOC_ALERT_MARK_AS_RESOLVED:
        client->AlertMarkAsResolved(alert);
        events_db->MarkAsResolved(alert.GetType());
        break;
    case csSMOC_TYPE_REGISTER:
        client->TypeRegister(alert_type, alert_basename);
        csLog::Log(csLog::Debug, "%s: Register custom type: %s (%s)",
            name.c_str(), alert_type.c_str(), alert_basename.c_str());
        events_db->InsertType(alert_type, alert_basename);
        RefreshAlertTypes();
        break;
    case csSMOC_TYPE_DEREGISTER:
        client->TypeDeregister(alert_type);
        csLog::Log(csLog::Debug, "%s: De-register custom type: %s",
            name.c_str(), alert_type.c_str());
        events_db->DeleteType(alert_type);
        RefreshAlertTypes();
        break;
    case csSMOC_OVERRIDE_SET:
        client->OverrideSet(type, flags);
        csLog::Log(csLog::Debug, "%s: Set alert level override: %u: 0x%08x",
            name.c_str(), type, flags);
        if (events_db->SelectOverride(type) == csEventsAlert::csAF_NULL)
            events_db->InsertOverride(type, flags);
        else
            events_db->UpdateOverride(type, flags);
        RefreshLevelOverrides();
        break;

    case csSMOC_OVERRIDE_CLEAR:
        client->OverrideClear(type);
        csLog::Log(csLog::Debug, "%s: Clear alert level override: %u",
            name.c_str(), type);
        events_db->DeleteOverride(type);
        RefreshLevelOverrides();
        break;

    default:
        csLog::Log(csLog::Warning,
            "%s: Unhandled op-code: %02x", name.c_str(), client->GetOpCode());
    }
}

void csPluginEvents::ProcessSysinfoRefresh(void)
{
    struct statvfs fs_info;
    struct sysinfo sys_info;
    float vol_used_pct = 0.0f;

    if (sysinfo(&sys_info) < 0) {
        csLog::Log(csLog::Warning, "%s: sysinfo: %s", name.c_str(), strerror(errno));
        return;
    }

    float loads[3];
    float load_shift = (float)(1 << SI_LOAD_SHIFT);
    loads[0] = ((float)sys_info.loads[0]) / load_shift;
    loads[1] = ((float)sys_info.loads[1]) / load_shift;
    loads[2] = ((float)sys_info.loads[2]) / load_shift;
    float swap_used_pct = ((float)sys_info.totalswap - (float)sys_info.freeswap) *
        100.0f / (float)sys_info.totalswap;

/*
    csLog::Log(csLog::Debug,
        "%s: System Information", name.c_str());
    csLog::Log(csLog::Debug,
        "%s: uptime: %ld", name.c_str(), sys_info.uptime);
    csLog::Log(csLog::Debug,
        "%s: load averages: %.02f %.02f %.02f", name.c_str(),
        loads[0], loads[1], loads[2]);
    csLog::Log(csLog::Debug,
        "%s: swap available: %ld", name.c_str(),
        sys_info.freeswap);
    csLog::Log(csLog::Debug,
        "%s: swap total: %ld, %.02f%% used", name.c_str(),
        sys_info.totalswap, swap_used_pct);
*/
    for (csEventsSysinfoConfigMap::iterator i = events_sysinfo.begin();
        i != events_sysinfo.end(); i++) {
        for (vector<csEventsSysinfoConfig *>::iterator j = i->second.begin();
            j != i->second.end(); j++) {
            switch (i->first) {
            case csEventsAlertSourceConfig_sysinfo::csSIK_LOAD_1M:
                ProcessSysinfoThreshold(i->first, (*j), loads[0]);
                break;
            case csEventsAlertSourceConfig_sysinfo::csSIK_LOAD_5M:
                ProcessSysinfoThreshold(i->first, (*j), loads[1]);
                break;
            case csEventsAlertSourceConfig_sysinfo::csSIK_LOAD_15M:
                ProcessSysinfoThreshold(i->first, (*j), loads[2]);
                break;
            case csEventsAlertSourceConfig_sysinfo::csSIK_SWAP_USAGE:
                ProcessSysinfoThreshold(i->first, (*j), swap_used_pct);
                break;
            case csEventsAlertSourceConfig_sysinfo::csSIK_VOL_USAGE:
                if (statvfs((*j)->path.c_str(), &fs_info) < 0) {
                    csLog::Log(csLog::Warning,
                        "%s: statvfs: %s", name.c_str(), strerror(errno));
                    break;
                }
                vol_used_pct = ((float)fs_info.f_blocks - (float)fs_info.f_bavail) *
                    100.0f / (float)fs_info.f_blocks;
                csLog::Log(csLog::Debug,
                    "%s: volume %s, used: %.02f%%",
                    name.c_str(), (*j)->path.c_str(),
                    fs_info.f_blocks, vol_used_pct);
                ProcessSysinfoThreshold(i->first, (*j), vol_used_pct);
                break;
            case csEventsAlertSourceConfig_sysinfo::csSIK_NULL:
            default:
                break;
            }
        }
    }
}

void csPluginEvents::ProcessSysinfoThreshold(
    csEventsAlertSourceConfig_sysinfo::csEventsAlertSource_sysinfo_key key,
    csEventsSysinfoConfig *config, float threshold)
{
    size_t pos;
    ostringstream value;
    string description;

    if (threshold >= config->threshold) {
        if (config->trigger_start_time == 0)
            config->trigger_start_time = time(NULL);
        else if (config->trigger_active) return;
        else if (time(NULL) - config->trigger_start_time > (time_t)config->duration) {
            csEventsAlert alert;
            alert.SetType(config->type);
            alert.SetFlag(config->level);
            if (config->auto_resolve)
                alert.SetFlag(csEventsAlert::csAF_FLG_AUTO_RESOLVE);
            config->trigger_active = true;

            map<string, string>::iterator text = config->text.find(locale);
            if (text != config->text.end())
                description = text->second;
            else {
                text = config->text.find("en");
                if (text != config->text.end())
                    description = text->second;
                else {
                    csLog::Log(csLog::Debug,
                        "%s: No localized text found for sysinfo alert",
                        name.c_str());
                    return;
                }
            }

            for (vector<string>::iterator i = events_sysinfo_keys.begin();
                i != events_sysinfo_keys.end(); i++) {

                value.str("");
                if ((*i) == "$threshold")
                    value << setprecision(4) << config->threshold;
                else if ((*i) == "$path")
                    value << config->path;
                else if ((*i) == "$swap_used" || (*i) == "$vol_used")
                    value << setprecision(4) << threshold;
                else
                    continue;

                while ((pos = description.find((*i))) != string::npos)
                    description.replace(pos, (*i).length(), value.str());
            }

            alert.SetDescription(description);
            alert.SetOrigin("internal-sysinfo");
            alert.SetBasename("csplugin-events");
            alert.SetUser();

            if (key == csEventsAlertSourceConfig_sysinfo::csSIK_VOL_USAGE)
                alert.SetUUID(config->path);

            InsertAlert(alert);
        }
    }
    else if (config->trigger_start_time > 0) {
        config->trigger_start_time = 0;
        if (config->auto_resolve && config->trigger_active) {
            config->trigger_active = false;
            events_db->MarkAsResolved(config->type);
            csLog::Log(csLog::Debug,
                "%s: Auto-resolved sysinfo alert",
                name.c_str());
        }
    }
}

void csPluginEvents::SyslogTextSubstitute(string &dst,
    csRegEx *rx, csAlertSourceConfig_syslog_pattern *rx_config)
{
    size_t pos;
    dst = rx_config->text;
    csAlertSourceConfig_syslog_match::iterator i;
    for (i = rx_config->match.begin(); i != rx_config->match.end(); i++) {
        if (strlen(rx->GetMatch(i->first)) == 0) {
            dst.clear();
            return;
        }
        while ((pos = dst.find(i->second)) != string::npos)
            dst.replace(pos, i->second.length(), rx->GetMatch(i->first));
    }
}

void csPluginEvents::RefreshAlertTypes(void)
{
    csAlertIdMap alert_types;
    events_db->SelectTypes(&alert_types);
    events_conf->MergeRegisteredAlertTypes(alert_types);
}

void csPluginEvents::RefreshLevelOverrides(void)
{
    overrides.clear();
    events_db->SelectOverrides(&overrides);

    csLog::Log(csLog::Debug, "%s: Level overrides:", name.c_str());
    for (csEventsLevelOverrideMap::iterator i = overrides.begin();
        i != overrides.end(); i++) {
        csLog::Log(csLog::Debug, "  %u: 0x%08x", i->first, i->second);
    }
}

void csPluginEvents::InsertAlert(csEventsAlert &alert)
{
    csEventsLevelOverrideMap::iterator i = overrides.find(alert.GetType());

    if (i != overrides.end()) {
        if (i->second == csEventsAlert::csAF_FLG_IGNORE) {
            csLog::Log(csLog::Debug, "%s: Level override ignore: %u",
                name.c_str(), i->first);
            return;
        }

        uint32_t flags = alert.GetFlags();
        flags &= ~(
            csEventsAlert::csAF_LVL_NORM |
            csEventsAlert::csAF_LVL_WARN |
            csEventsAlert::csAF_LVL_CRIT
        );
        flags |= i->second;
        alert.SetFlags(flags);
    }

    events_db->InsertAlert(alert);
}

csPluginInit(csPluginEvents);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
