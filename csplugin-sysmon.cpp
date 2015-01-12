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

#include <unistd.h>
#include <fcntl.h>
#include <linux/un.h>
#include <sqlite3.h>

#include "sysmon-conf.h"
#include "sysmon-alert.h"
#include "sysmon-db.h"
#include "sysmon-socket.h"
#include "sysmon-syslog.h"
#include "csplugin-sysmon.h"

csPluginSysMon::csPluginSysMon(const string &name,
    csEventClient *parent, size_t stack_size)
    : csPlugin(name, parent, stack_size),
    sysmon_conf(NULL), sysmon_db(NULL), sysmon_syslog(NULL),
    sysmon_socket_server(NULL), fh_loadavg(NULL)
{
    ::csGetLocale(locale);
    size_t uscore_delim = locale.find_first_of('_');
    if (uscore_delim != string::npos) {
        string temp;
        ::csGetLocale(temp);
        temp = locale.substr(0, uscore_delim);
        locale = temp;
    }

    csLog::Log(csLog::Debug, "%s: Initialized (locale: %s)",
        name.c_str(), locale.c_str());
}

csPluginSysMon::~csPluginSysMon()
{
    Join();

    if (sysmon_conf != NULL) delete sysmon_conf;
    if (sysmon_db != NULL) delete sysmon_db;
    if (sysmon_syslog != NULL) delete sysmon_syslog;
    if (sysmon_socket_server != NULL) delete sysmon_socket_server;
    for (csPluginSysMonClientMap::iterator i = sysmon_socket_client.begin();
        i != sysmon_socket_client.end(); i++) delete i->second;
    for (csSysMonSyslogRegExVector::iterator i = sysmon_syslog_rx.begin();
        i != sysmon_syslog_rx.end(); i++) {
        if ((*i)->rx) delete (*i)->rx;
        if ((*i)->rx_en) delete (*i)->rx_en;
        delete (*i);
    }
}

void csPluginSysMon::SetConfigurationFile(const string &conf_filename)
{
    if (sysmon_conf != NULL) delete sysmon_conf;

    csPluginXmlParser *parser = new csPluginXmlParser();
    sysmon_conf = new csSysMonConf(this, conf_filename.c_str(), parser);
    parser->SetConf(dynamic_cast<csConf *>(sysmon_conf));
    sysmon_conf->Reload();

    if (sysmon_db != NULL) delete sysmon_db;
    sysmon_db = new csSysMonDb_sqlite(sysmon_conf->GetSqliteDbFilename());
    if (sysmon_syslog != NULL) delete sysmon_syslog;
    sysmon_syslog = new csSysMonSyslog(sysmon_conf->GetSyslogSocketPath());

    try {
        if (sysmon_socket_server != NULL) delete sysmon_socket_server;
        sysmon_socket_server = new csSysMonSocketServer(
            sysmon_conf->GetSysMonSocketPath());
    } catch (csSysMonSocketException &e) {
        csLog::Log(csLog::Error,
            "%s: %s: %s", name.c_str(), e.estring.c_str(), e.what());
    }

    csAlertSourceConfigVector alert_sources;
    sysmon_conf->GetAlertSourceConfigs(alert_sources);

    int compiled = 0;
    csAlertSourceMap_syslog_pattern *patterns;

    for (csAlertSourceConfigVector::iterator i = alert_sources.begin();
        i != alert_sources.end(); i++) {

        if ((*i)->GetType() != csSysMonAlertSourceConfig::csAST_SYSLOG) continue;

        csSysMonAlertSourceConfig_syslog *syslog_config;
        syslog_config = reinterpret_cast<csSysMonAlertSourceConfig_syslog *>((*i));

        patterns = syslog_config->GetPatterns();

        for (csAlertSourceMap_syslog_pattern::iterator j = patterns->begin();
            j != patterns->end(); j++) {

            csSysMonSyslogRegEx *entry = NULL;

            try {
                entry = new csSysMonSyslogRegEx;
                memset(entry, 0, sizeof(csSysMonSyslogRegEx));
                entry->type = syslog_config->GetAlertType();

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

                compiled++;
            }
            catch (csException &e) {
                csLog::Log(csLog::Error,
                    "%s: Regular expression compilation failed: %s",
                        name.c_str(), e.what());
                if (entry != NULL) delete entry;
                entry = NULL;
            }

            if (entry != NULL)
                sysmon_syslog_rx.push_back(entry);
        }
    }

    csLog::Log(csLog::Debug,
        "%s: Compiled %d regular expressions", name.c_str(), compiled);
}

void *csPluginSysMon::Entry(void)
{
    int rc;
    fd_set fds_read;
    struct timeval tv;

    csLog::Log(csLog::Debug, "%s: Started", name.c_str());

    try {
        sysmon_db->Open();
        if (sysmon_conf->InitDb()) sysmon_db->Drop();
        sysmon_db->Create();
    }
    catch (csSysMonDbException &e) {
        csLog::Log(csLog::Error,
            "%s: Database exception: %s", name.c_str(), e.estring.c_str());
    }

    csTimer *purge_timer = new csTimer(
        _CSPLUGIN_SYSMON_PURGE_TIMER, 3, 3, this
    );
    purge_timer->Start();
    csTimer *sysdata_timer = new csTimer(
        _CSPLUGIN_SYSMON_SYSDATA_TIMER, 10, 10, this
    );
    sysdata_timer->Start();

    for (bool run = true; run; ) {

        int max_fd = sysmon_socket_server->GetDescriptor();

        FD_ZERO(&fds_read);
        FD_SET(max_fd, &fds_read);

        for (csPluginSysMonClientMap::iterator i = sysmon_socket_client.begin();
            i != sysmon_socket_client.end(); i++) {
            FD_SET(i->first, &fds_read);
            if (i->first > max_fd) max_fd = i->first;
        }

        FD_SET(sysmon_syslog->GetDescriptor(), &fds_read);
        if (sysmon_syslog->GetDescriptor() > max_fd)
            max_fd = sysmon_syslog->GetDescriptor();

        tv.tv_sec = 1; tv.tv_usec = 0;

        rc = select(max_fd + 1, &fds_read, NULL, NULL, &tv);

        if (rc > 0) ProcessEventSelect(fds_read);

        csTimer *timer;
        csEvent *event = EventPop();

        if (event != NULL) {
            switch (event->GetId()) {
            case csEVENT_QUIT:
                csLog::Log(csLog::Debug, "%s: Terminated.", name.c_str());
                run = false;
                break;

            case csEVENT_TIMER:
                timer = static_cast<csEventTimer *>(event)->GetTimer();

                if (timer->GetId() == _CSPLUGIN_SYSMON_PURGE_TIMER) {
                    sysmon_db->PurgeAlerts(csSysMonAlert(),
                        time(NULL) - sysmon_conf->GetMaxAgeTTL());
                } else if (timer->GetId() == _CSPLUGIN_SYSMON_SYSDATA_TIMER) {
                }
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

    return NULL;
}

void csPluginSysMon::ProcessEventSelect(fd_set &fds)
{
    vector<string> syslog_messages;
    csPluginSysMonClientMap::iterator sci;

    try {
        if (FD_ISSET(sysmon_syslog->GetDescriptor(), &fds)) {

            sysmon_syslog->Read(syslog_messages);

            for (vector<string>::iterator i = syslog_messages.begin();
                i != syslog_messages.end(); i++) {
                for (csSysMonSyslogRegExVector::iterator j = sysmon_syslog_rx.begin();
                    j != sysmon_syslog_rx.end(); j++) {

                    csRegEx *rx = (*j)->rx;
                    csAlertSourceConfig_syslog_pattern *rx_config = (*j)->config;
                    if (rx == NULL) {
                        rx = (*j)->rx_en;
                        rx_config = (*j)->config_en;
                    }
                    if (rx == NULL) continue;
                    if (rx->Execute((*i).c_str()) != 0) continue;

                    string text;
                    SyslogTextSubstitute(text, rx, rx_config);
                    if (text.length() == 0) continue;

                    csLog::Log(csLog::Debug, "%s: %s", name.c_str(), (*i).c_str());
                    csLog::Log(csLog::Debug, "%s: %s", name.c_str(), text.c_str());

                    csSysMonAlert alert;
                    alert.SetType((*j)->type);
                    alert.SetDescription(text);

                    sysmon_db->InsertAlert(alert);

                    break;
                }
            }
        }

        for (csPluginSysMonClientMap::iterator i = sysmon_socket_client.begin();
            i != sysmon_socket_client.end(); i++) {
            if (FD_ISSET(i->first, &fds)) ProcessClientRequest(i->second);
        }

        if (FD_ISSET(sysmon_socket_server->GetDescriptor(), &fds)) {

            csSysMonSocketClient *client = sysmon_socket_server->Accept();

            if (client != NULL) {
                sysmon_socket_client[client->GetDescriptor()] = client;
                csLog::Log(csLog::Debug, "%s: Accepted new client connection",
                    name.c_str());
            }
       }
    }
    catch (csSysMonSocketHangupException &e) {
        csLog::Log(csLog::Warning, "%s: Socket hang-up: %d",
            name.c_str(), e.GetDescriptor());
        sci = sysmon_socket_client.find(e.GetDescriptor());
        if (sci == sysmon_socket_client.end()) {
            csLog::Log(csLog::Error, "%s: Socket hang-up on unknown descriptor: %d",
                name.c_str(), e.GetDescriptor());
        }
        else {
            delete sci->second;
            sysmon_socket_client.erase(sci);
        }
    }
    catch (csSysMonSocketTimeoutException &e) {
        csLog::Log(csLog::Error, "%s: Socket time-out: %d",
            name.c_str(), e.GetDescriptor());
        sci = sysmon_socket_client.find(e.GetDescriptor());
        if (sci == sysmon_socket_client.end()) {
            csLog::Log(csLog::Error, "%s: Socket time-out on unknown descriptor: %d",
                name.c_str(), e.GetDescriptor());
        }
        else {
            delete sci->second;
            sysmon_socket_client.erase(sci);
        }
    }
    catch (csSysMonSocketProtocolException &e) {
        csLog::Log(csLog::Error, "%s: Protocol error: %d: %s",
            name.c_str(), e.GetDescriptor(), e.estring.c_str());
        sci = sysmon_socket_client.find(e.GetDescriptor());
        if (sci == sysmon_socket_client.end()) {
            csLog::Log(csLog::Error, "%s: Protocol error on unknown descriptor: %d",
                name.c_str(), e.GetDescriptor());
        }
        else {
            delete sci->second;
            sysmon_socket_client.erase(sci);
        }
    }
    catch (csSysMonSocketException &e) {
        csLog::Log(csLog::Error, "%s: Socket exception: %s: %s",
            name.c_str(), e.estring.c_str(), e.what());
    }
    catch (csSysMonDbException &e) {
        csLog::Log(csLog::Error, "%s: Database exception: %s",
            name.c_str(), e.estring.c_str());
    }
    catch (csException &e) {
        csLog::Log(csLog::Error, "%s: Exception: %s",
            name.c_str(), e.estring.c_str());
    }
}

void csPluginSysMon::ProcessClientRequest(csSysMonSocketClient *client)
{
    csSysMonAlert alert;

    if (client->GetProtoVersion() == 0) {
        client->VersionExchange();

        csLog::Log(csLog::Debug, "%s: Client version: 0x%08x",
            name.c_str(), client->GetProtoVersion());

        return;
    }

    switch (client->ReadPacket()) {
    case csSMOC_ALERT_INSERT:
        client->AlertInsert(alert);
        sysmon_db->InsertAlert(alert);
        break;
    case csSMOC_ALERT_SELECT:
        client->AlertSelect(sysmon_db);
        break;
    case csSMOC_ALERT_MARK_AS_READ:
        client->AlertMarkAsRead(alert);
        sysmon_db->MarkAsRead(alert.GetId());
        break;
    default:
        csLog::Log(csLog::Warning,
            "%s: Unhandled op-code: %02x", name.c_str(), client->GetOpCode());
    }
}

void csPluginSysMon::SyslogTextSubstitute(string &dst,
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

csPluginInit(csPluginSysMon);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
