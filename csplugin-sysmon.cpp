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

#include "sysmon-conf.h"
#include "sysmon-alert.h"
#include "sysmon-syslog.h"
#include "csplugin-sysmon.h"

csPluginSysMon::csPluginSysMon(const string &name,
    csEventClient *parent, size_t stack_size)
    : csPlugin(name, parent, stack_size), conf(NULL), sysmon_syslog(NULL)
{
    sysmon_syslog = new csSysMonSyslog(this, "/tmp/rsyslogd.sock");

    csLog::Log(csLog::Debug, "%s: Initialized.", name.c_str());
}

csPluginSysMon::~csPluginSysMon()
{
    Join();

    if (conf) delete conf;
    if (sysmon_syslog) delete sysmon_syslog;
}

void csPluginSysMon::SetConfigurationFile(const string &conf_filename)
{
    if (conf != NULL) delete conf;

    csPluginXmlParser *parser = new csPluginXmlParser();
    conf = new csSysMonConf(this, conf_filename.c_str(), parser);
    parser->SetConf(dynamic_cast<csConf *>(conf));
    conf->Reload();
}

void *csPluginSysMon::Entry(void)
{
    vector<string> syslog_messages;
    csLog::Log(csLog::Info, "%s: Running.", name.c_str());

    unsigned long loops = 0ul;
    GetStateVar("loops", loops);
    csLog::Log(csLog::Debug, "%s: loops: %lu", name.c_str(), loops);

    csTimer *timer = new csTimer(500, 3, 3, this);
    timer->Start();

    for (bool run = true; run; loops++) {
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
                i != syslog_messages.end(); i++)
                csLog::Log(csLog::Debug, (*i).c_str());
            break;

        case csEVENT_TIMER:
            csLog::Log(csLog::Debug, "%s: Tick: %lu", name.c_str(),
                static_cast<csEventTimer *>(event)->GetTimer()->GetId());
            break;
        }

        EventDestroy(event);
    }

    delete timer;

    SetStateVar("loops", loops);
    csLog::Log(csLog::Debug, "%s: loops: %lu", name.c_str(), loops);

    return NULL;
}

csPluginInit(csPluginSysMon);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
