// ClearSync: System Monitor controller.
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

#include <iostream>
#include <sstream>

#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <linux/un.h>
#include <sqlite3.h>

#include "events-conf.h"
#include "events-alert.h"
#include "events-db.h"
#include "events-socket.h"
#include "events-syslog.h"
#include "csplugin-events.h"
#include "eventsctl.h"

static bool debug = false;
static char *conf_filename = NULL;

static void usage(int rc = 0, bool version = false)
{
    csLog::Log(csLog::Info, "SysMon Control v%s", PACKAGE_VERSION);
    csLog::Log(csLog::Info, "Copyright (C) 2014 ClearFoundation [%s %s]",
        __DATE__, __TIME__);
    if (version) {
        csLog::Log(csLog::Info,
            "  This program comes with ABSOLUTELY NO WARRANTY.");
        csLog::Log(csLog::Info,
            "  This is free software, and you are welcome to redistribute it");
        csLog::Log(csLog::Info,
            "  under certain conditions according to the GNU General Public");
        csLog::Log(csLog::Info,
            "  License version 3, or (at your option) any later version.");
#ifdef PACKAGE_BUGREPORT
        csLog::Log(csLog::Info, "Report bugs to: %s", PACKAGE_BUGREPORT);
#endif
    }
    else {
        csLog::Log(csLog::Info,
            "  -V, --version");
        csLog::Log(csLog::Info,
            "    Display program version and license information.");
        csLog::Log(csLog::Info,
            "  -c <file>, --config <file>");
        csLog::Log(csLog::Info,
            "    Specify an alternate configuration file.");
        csLog::Log(csLog::Info,
            "  -d, --debug");
        csLog::Log(csLog::Info,
            "    Enable debugging messages and remain in the foreground.");

        csLog::Log(csLog::Info, "\nSend an alert:");
        csLog::Log(csLog::Info,
            "  -s, --send");
        csLog::Log(csLog::Info,
            "    Send an alert.");
        csLog::Log(csLog::Info,
            "  -p, --persistent");
        csLog::Log(csLog::Info,
            "    Enable persistent flag.");
        csLog::Log(csLog::Info,
            "  -t <type>, --type <type>");
        csLog::Log(csLog::Info,
            "    Specify an alert type.  Try \"list\" to show available types.");
        csLog::Log(csLog::Info,
            "  -u <user>, --user <user>");
        csLog::Log(csLog::Info,
            "    Specify an optional username or UID.");
        csLog::Log(csLog::Info,
            "  -U <uuid>, --uuid <uuid>");
        csLog::Log(csLog::Info,
            "    Specify an optional UUID.");
        csLog::Log(csLog::Info,
            "  -i <basename>, --basename <basename>");
        csLog::Log(csLog::Info,
            "    Specify an optional basename.");

        csLog::Log(csLog::Info, "\nMark alert as read:");
        csLog::Log(csLog::Info,
            "  -m <id>, --mark-read <id>");

        csLog::Log(csLog::Info, "\nList all alerts:");
        csLog::Log(csLog::Info,
            "  -l, --list");
    }
    exit(rc);
}

int main(int argc, char *argv[])
{
    int rc;

    int64_t alert_id = 0;
    uint32_t alert_flags = csEventsAlert::csAF_LVL_NORM;
    string alert_type, alert_user, alert_origin, alert_basename, alert_uuid;
    ostringstream alert_desc;

    csEventsCtl::csEventsCtlMode mode = csEventsCtl::CTLM_NULL;

    static struct option options[] =
    {
        { "version", 0, 0, 'V' },
        { "config", 1, 0, 'c' },
        { "debug", 0, 0, 'd' },
        { "help", 0, 0, 'h' },
        // Send an alert
        { "send", 0, 0, 's' },
        { "persistent", 0, 0, 'p' },
        { "type", 1, 0, 't' },
        { "user", 1, 0, 'u' },
        { "origin", 1, 0, 'o' },
        { "basename", 1, 0, 'b' },
        { "uuid", 1, 0, 'U' },
        // Mark alert as read
        { "mark-read", 1, 0, 'm' },
        // List alerts
        { "list", 0, 0, 'l' },

        { NULL, 0, 0, 0 }
    };

    csLog *log_stdout = new csLog();
    log_stdout->SetMask(csLog::Info | csLog::Warning | csLog::Error);

    conf_filename = strdup("/etc/clearsync.d/csplugin-events.conf");

    for (optind = 1;; ) {
        int o = 0;
        if ((rc = getopt_long(argc, argv,
            "Vc:dh?spt:u:U:b:o:m:l", options, &o)) == -1) break;
        switch (rc) {
        case 'V':
            usage(0, true);
        case 'c':
            free(conf_filename);
            conf_filename = strdup(optarg);
            break;
        case 'd':
            debug = true;
            log_stdout->SetMask(
                csLog::Info | csLog::Warning | csLog::Error | csLog::Debug);
            break;
        case '?':
            csLog::Log(csLog::Info,
                "Try %s --help for more information.", argv[0]);
            return 1;
        case 'h':
            usage();
        case 's':
            if (mode != csEventsCtl::CTLM_NULL) usage(1);
            mode = csEventsCtl::CTLM_SEND;
            break;
        case 'p':
            alert_flags |= csEventsAlert::csAF_FLG_PERSIST;
            break;
        case 't':
            alert_type = optarg;
            break;
        case 'u':
            alert_user = optarg;
            break;
        case 'U':
            alert_uuid = optarg;
            break;
        case 'b':
            alert_basename = optarg;
            break;
        case 'o':
            alert_origin = optarg;
            break;
        case 'm':
            mode = csEventsCtl::CTLM_MARK_AS_READ;
            alert_id = (int64_t)atoll(optarg);
            break;
        case 'l':
            mode = csEventsCtl::CTLM_LIST_ALERTS;
            break;
        }
    }

    csEventsCtl events_ctl;
    csEventsAlert alert;

    if (alert_type == "list") mode = csEventsCtl::CTLM_LIST_TYPES;

    if (mode == csEventsCtl::CTLM_SEND) {
        if (argc > optind) alert_desc << argv[optind];
        for (int i = optind + 1; i < argc; i++) alert_desc << " " << argv[i];
    }

    rc = events_ctl.Exec(mode, alert_id,
        alert_flags, alert_type, alert_user, alert_origin, alert_basename, alert_uuid, alert_desc);

    free(conf_filename);

    delete log_stdout;
    return rc;
}

csEventsCtl::csEventsCtl()
    : events_conf(NULL), events_socket(NULL)
{
    csPluginXmlParser *parser = new csPluginXmlParser();
    events_conf = new csEventsConf(NULL, conf_filename, parser);
    parser->SetConf(dynamic_cast<csConf *>(events_conf));
    events_conf->Reload();
}

csEventsCtl::~csEventsCtl()
{
    if (events_socket) delete events_socket;
    if (events_conf) delete events_conf;
}

int csEventsCtl::Exec(csEventsCtlMode mode,
        int64_t id, uint32_t flags, const string &type,
        const string &user, const string &origin, const string &basename, const string &uuid,
        ostringstream &desc)
{
    csEventsAlert alert;
//    uint32_t alert_type = 0;
    csAlertIdMap alert_types;
    vector<csEventsAlert *> result;
    char alert_flags[3];
    struct tm tm_local;
    char date_time[_CS_MAX_TIMESTAMP];
    string alert_type_name, alert_prio;

    if (mode == CTLM_SEND || mode == CTLM_MARK_AS_READ || mode == CTLM_LIST_ALERTS) {
        events_socket = new csEventsSocketClient(events_conf->GetSysMonSocketPath());
        events_socket->Connect();

        switch (events_socket->VersionExchange()) {
        case csSMPR_OK:
            csLog::Log(csLog::Debug, "Protocol version: OK");
            break;
        case csSMPR_VERSION_MISMATCH:
            csLog::Log(csLog::Debug, "Protocol version: mis-match");
            return 1;
        default:
            csLog::Log(csLog::Debug, "Unexpected reply.");
            return 1;
        }
    }

    try {
        switch (mode) {
        case CTLM_SEND:
            alert.SetFlags(flags);
            alert.SetType(events_conf->GetAlertId(type));
            if (user.length()) alert.SetUser(user);
            else alert.SetUser(geteuid());
            if (origin.length()) alert.SetOrigin(origin);
            if (basename.length()) alert.SetBasename(basename);
            if (uuid.length()) alert.SetUUID(uuid);
            if (desc.tellp()) alert.SetDescription(desc.str());

            events_socket->AlertInsert(alert);

            break;

        case CTLM_MARK_AS_READ:
            alert.SetId(id);

            events_socket->AlertMarkAsRead(alert);

            break;

        case CTLM_LIST_TYPES:
            csLog::Log(csLog::Info, "Alert Types:");
            events_conf->GetAlertTypes(alert_types);
            for (csAlertIdMap::iterator i = alert_types.begin(); i != alert_types.end(); i++)
                csLog::Log(csLog::Info, "  %s", i->second.c_str());
            break;

        case CTLM_LIST_ALERTS:
            events_socket->AlertSelect("ORDER BY stamp", result);
            if (result.size() == 0) {
                csLog::Log(csLog::Info, "No alerts in database.");
                break;
            }
            for (vector<csEventsAlert *>::iterator i = result.begin();
                i != result.end(); i++) {

                const time_t stamp = (*i)->GetStamp();
                if (localtime_r(&stamp, &tm_local) == NULL) {
                    csLog::Log(csLog::Error, "Error creating local time: %s",
                        strerror(errno));
                    continue;
                }

                if (strftime(date_time, _CS_MAX_TIMESTAMP, "%c", &tm_local) <= 0) {
                    csLog::Log(csLog::Error, "Error creating string time: %s",
                        strerror(errno));
                    continue;
                }

                try {
                    alert_type_name = events_conf->GetAlertType((*i)->GetType());
                } catch (csException &e) {
                    csLog::Log(csLog::Error, "Unknown alert type ID: %u",
                        (*i)->GetType());
                    alert_type_name = "UNKNOWN";
                }

                if ((*i)->GetFlags() & csEventsAlert::csAF_LVL_NORM)
                    alert_prio = "";
                else if ((*i)->GetFlags() & csEventsAlert::csAF_LVL_WARN)
                    alert_prio = "WARNING";
                else if ((*i)->GetFlags() & csEventsAlert::csAF_LVL_WARN)
                    alert_prio = "CRITICAL";

                alert_flags[0] = ((*i)->GetFlags() & csEventsAlert::csAF_FLG_PERSIST) ? 'p' : '-';
                alert_flags[1] = ((*i)->GetFlags() & csEventsAlert::csAF_FLG_READ) ? 'r' : '-';
                alert_flags[2] = '\0';

                csLog::Log(csLog::Info, "#%-10llu%-30s%s%s[%s] %s",
                    (*i)->GetId(), date_time, alert_prio.c_str(),
                    (alert_prio.length()) ? ": " : " ",
                    alert_flags, alert_type_name.c_str());
                csLog::Log(csLog::Info, (*i)->GetDescription().c_str());
                csLog::Log(csLog::Info, "");
            }
            break;
            
        default:
            csLog::Log(csLog::Error, "Invalid mode or no mode specified.");
            csLog::Log(csLog::Info, "Try --help for usage information.");
            return 1;
        }
    } catch (csEventsSocketException &e) {
        csLog::Log(csLog::Error, "Exception: %s: %s", e.estring.c_str(), e.what());
        return 1;
    } catch (csException &e) {
        csLog::Log(csLog::Error, "Exception: %s", e.estring.c_str());
        return 1;
    }

    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
