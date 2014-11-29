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
#include "sysmon-alert-source.h"
#include "sysmon-db.h"
#include "sysmon-socket.h"
#include "sysmon-syslog.h"
#include "csplugin-sysmon.h"

csPluginSysMon::csPluginSysMon(const string &name,
    csEventClient *parent, size_t stack_size)
    : csPlugin(name, parent, stack_size),
    sysmon_conf(NULL), sysmon_db(NULL), sysmon_syslog(NULL)
{
    csLog::Log(csLog::Debug, "%s: Initialized.", name.c_str());
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
        sysmon_socket_server = new csSysMonSocketServer(sysmon_conf->GetSysMonSocketPath());
    } catch (csSysMonSocketException &e) {
        csLog::Log(csLog::Error,
            "%s: %s: %s", name.c_str(), e.estring.c_str(), e.what());
    }
}

void *csPluginSysMon::Entry(void)
{
    int rc;
    fd_set fds_read;
    struct timeval tv;

    csLog::Log(csLog::Debug, "%s: Started", name.c_str());

    try {
        sysmon_db->Open();
        sysmon_db->Drop();
        sysmon_db->Create();
    }
    catch (csSysMonDbException &e) {
        csLog::Log(csLog::Error,
            "%s: Database exception: %s", name.c_str(), e.estring.c_str());
    }

//    unsigned long loops = 0ul;
//    GetStateVar("loops", loops);
//    csLog::Log(csLog::Debug, "%s: loops: %lu", name.c_str(), loops);

    csTimer *purge_timer = new csTimer(500, 3, 3, this);
    purge_timer->Start();

    bool run = true;
    while (run) {
        int max_fd = 0;

        FD_ZERO(&fds_read);

        max_fd = sysmon_socket_server->GetDescriptor();
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

        csEvent *event = EventPop();
        if (event != NULL) {
            switch (event->GetId()) {
            case csEVENT_QUIT:
                csLog::Log(csLog::Debug, "%s: Terminated.", name.c_str());
                run = false;
                break;

            case csEVENT_TIMER:
                sysmon_db->PurgeAlerts(csSysMonAlert(),
                    time(NULL) - sysmon_conf->GetMaxAgeTTL());
                break;
            }

            EventDestroy(event);
        }

        // Select error?
        if (rc == -1) {
            csLog::Log(csLog::Warning, "%s: select: %s", name.c_str(), strerror(rc));
            usleep(10000);
        }
    }

    delete purge_timer;

//    SetStateVar("loops", loops);
//    csLog::Log(csLog::Debug, "%s: loops: %lu", name.c_str(), loops);

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
                csLog::Log(csLog::Debug, (*i).c_str());
                InsertAlert((*i));
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

void csPluginSysMon::InsertAlert(const string &desc)
{
    try {
        csSysMonAlert alert;
        alert.SetDescription(desc);
        alert.SetType(sysmon_conf->GetAlertId("SYSLOG_TEST"));
        sysmon_db->InsertAlert(alert);
        alert.SetId(sysmon_db->GetLastId("alert"));
    }
    catch (csSysMonDbException &e) {
        csLog::Log(csLog::Error,
            "%s: Database exception: %s", name.c_str(), e.estring.c_str());
    }
    catch (csException &e) {
        csLog::Log(csLog::Error,
            "%s: Database exception: %s", name.c_str(), e.estring.c_str());
    }
}

csPluginInit(csPluginSysMon);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
