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
#include <clearsync/csselect.h>

#include <sstream>

#include <sqlite3.h>

#include "sysmon-conf.h"
#include "sysmon-alert.h"
#include "sysmon-alert-source.h"
#include "sysmon-db.h"
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
    sysmon_syslog = new csSysMonSyslog(this, sysmon_conf->GetSyslogSocketPath());
}

void *csPluginSysMon::Entry(void)
{
    vector<string> syslog_messages;
    csLog::Log(csLog::Info, "%s: Running.", name.c_str());

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
        csEvent *event = EventPopWait();

        switch (event->GetId()) {
        case csEVENT_QUIT:
            csLog::Log(csLog::Info, "%s: Terminated.", name.c_str());
            run = false;
            break;

        case csEVENT_SELECT:
            syslog_messages.clear();
            sysmon_syslog->Read(syslog_messages);
            for (vector<string>::iterator i = syslog_messages.begin();
                i != syslog_messages.end(); i++) {
                csLog::Log(csLog::Debug, (*i).c_str());
                InsertAlert((*i));
            }
            break;

        case csEVENT_TIMER:
            sysmon_db->PurgeAlerts(csSysMonAlert(),
                time(NULL) - sysmon_conf->GetMaxAgeTTL());
            break;
        }

        EventDestroy(event);
    }

    delete purge_timer;

//    SetStateVar("loops", loops);
//    csLog::Log(csLog::Debug, "%s: loops: %lu", name.c_str(), loops);

    return NULL;
}

void csPluginSysMon::InsertAlert(const string &desc)
{
    try {
        csSysMonAlert alert;
        alert.SetDescription(desc);
        alert.SetFlag(csSysMonAlert::csAF_FLG_READ);
        sysmon_db->InsertAlert(alert);
        alert.SetId(sysmon_db->GetLastId("alert"));
    }
    catch (csSysMonDbException &e) {
        csLog::Log(csLog::Error, "%s: Database exception: %s", name.c_str(), e.estring.c_str());
    }
    catch (csException &e) {
        csLog::Log(csLog::Error, "%s: Database exception: %s", name.c_str(), e.estring.c_str());
    }
}

csPluginInit(csPluginSysMon);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
