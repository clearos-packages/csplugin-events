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

#ifndef _CSPLUGIN_SYSMON_H
#define _CSPLUGIN_SYSMON_H

typedef map<int, csSysMonSocketClient *> csPluginSysMonClientMap;
typedef map<int, string> csSysMonSyslogTextSubIndexMap;

typedef struct
{
    uint32_t type;
    csRegEx *rx;
    csRegEx *rx_en;
    csAlertSourceConfig_syslog_pattern *config;
    csAlertSourceConfig_syslog_pattern *config_en;
} csSysMonSyslogRegEx;

typedef vector<csSysMonSyslogRegEx *> csSysMonSyslogRegExVector;

class csPluginSysMon : public csPlugin
{
public:
    csPluginSysMon(const string &name,
        csEventClient *parent, size_t stack_size);
    virtual ~csPluginSysMon();

    virtual void SetConfigurationFile(const string &conf_filename);

    virtual void *Entry(void);

protected:
    friend class csPluginXmlParser;

    void ProcessEventSelect(fd_set &fds);
    void ProcessClientRequest(csSysMonSocketClient *client);

    void SyslogTextSubstitute(string &dst,
        csRegEx *rx, csAlertSourceConfig_syslog_pattern *rx_config);

    string locale;
    csSysMonConf *sysmon_conf;
    csSysMonDb *sysmon_db;
    csSysMonSyslog *sysmon_syslog;
    csSysMonSocketServer *sysmon_socket_server;
    csPluginSysMonClientMap sysmon_socket_client;
    csSysMonSyslogRegExVector sysmon_syslog_rx;
};

#endif // _CSPLUGIN_SYSMON_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
