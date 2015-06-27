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

#ifndef _CSPLUGIN_EVENTS_H
#define _CSPLUGIN_EVENTS_H

#define _CSPLUGIN_EVENTS_PURGE_TIMER_ID     500
#define _CSPLUGIN_EVENTS_PURGE_TIMER        60
#define _CSPLUGIN_EVENTS_SYSINFO_TIMER_ID   501
#define _CSPLUGIN_EVENTS_SYSINFO_TIMER      5

typedef map<int, csEventsSocketClient *> csPluginEventsClientMap;
typedef map<int, string> csEventsSyslogTextSubIndexMap;

typedef struct
{
    uint32_t type;
    uint32_t level;
    bool exclude;
    bool auto_resolve;
    csRegEx *rx;
    csRegEx *rx_en;
    csAlertSourceConfig_syslog_pattern *config;
    csAlertSourceConfig_syslog_pattern *config_en;
} csEventsSyslogRegEx;

typedef vector<csEventsSyslogRegEx *> csEventsSyslogRegExVector;

typedef struct
{
    uint32_t type;
    uint32_t level;
    bool auto_resolve;
    float threshold;
    int duration;
    time_t trigger_start_time;
    bool trigger_active;
    map<string, string> text;
    string path;
} csEventsSysinfoConfig;

typedef map<csEventsAlertSourceConfig_sysinfo::csEventsAlertSource_sysinfo_key, vector<csEventsSysinfoConfig *> > csEventsSysinfoConfigMap;

class csPluginEvents : public csPlugin
{
public:
    csPluginEvents(const string &name,
        csEventClient *parent, size_t stack_size);
    virtual ~csPluginEvents();

    virtual void SetConfigurationFile(const string &conf_filename);

    virtual void *Entry(void);

protected:
    friend class csPluginXmlParser;

    void LoadAlertConfig(csEventsAlertSourceConfig_syslog *syslog_config);
    void LoadAlertConfig(csEventsAlertSourceConfig_sysinfo *sysinfo_config);

    void ProcessEventSelect(fd_set &fds);
    void ProcessClientRequest(csEventsSocketClient *client);
    void ProcessSysinfoRefresh(void);
    void ProcessSysinfoThreshold(
        csEventsAlertSourceConfig_sysinfo::csEventsAlertSource_sysinfo_key key,
        csEventsSysinfoConfig *config, float threshold);

    void SyslogTextSubstitute(string &dst,
        csRegEx *rx, csAlertSourceConfig_syslog_pattern *rx_config);

    string locale;
    csEventsConf *events_conf;
    csEventsDb *events_db;
    csEventsSyslog *events_syslog;
    csEventsSocketServer *events_socket_server;
    csPluginEventsClientMap events_socket_client;
    csEventsSyslogRegExVector events_syslog_rx;
    csEventsSysinfoConfigMap events_sysinfo;
    vector<string> events_sysinfo_keys;
};

#endif // _CSPLUGIN_EVENTS_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
