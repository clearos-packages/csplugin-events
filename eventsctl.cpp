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
#include <locale>
#include <algorithm>

#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <linux/un.h>

#include <sqlite3.h>
#include <openssl/sha.h>

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
    csLog::Log(csLog::Info, "Events Control v%s", PACKAGE_VERSION);
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

        csLog::Log(csLog::Info, "\nSend an alert:\n  # eventsctl -s <options> <description text>\n");
        csLog::Log(csLog::Info,
            "  -s, --send");
        csLog::Log(csLog::Info,
            "    Send an alert.");
        csLog::Log(csLog::Info,
            "  -t <type>, --type <type>");
        csLog::Log(csLog::Info,
            "    Specify an alert type.  Specify \"list\" to show registered types.");
        csLog::Log(csLog::Info,
            "  -l <level>, --level <level>");
        csLog::Log(csLog::Info,
            "    Specify an alert level; NORMal, WARNing, or CRITical.");
        csLog::Log(csLog::Info,
            "  -u <user>, --user <user>");
        csLog::Log(csLog::Info,
            "    Specify an optional username or UID.");
        csLog::Log(csLog::Info,
            "  -U <uuid>, --uuid <uuid>");
        csLog::Log(csLog::Info,
            "    Specify an optional UUID.");
        csLog::Log(csLog::Info,
            "  -o <origin>, --origin <origin>");
        csLog::Log(csLog::Info,
            "    Specify an optional origin.");
        csLog::Log(csLog::Info,
            "  -b <basename>, --basename <basename>");
        csLog::Log(csLog::Info,
            "    Specify an optional basename.");
        csLog::Log(csLog::Info,
            "  -a, --auto-resolve");
        csLog::Log(csLog::Info,
            "    Alert will auto-resolve (ex: firewall panic mode).");

        csLog::Log(csLog::Info, "\nMark alert type as resolved:");
        csLog::Log(csLog::Info,
            "  -r, --mark-resolved");
        csLog::Log(csLog::Info,
            "  -t <type>, --type <type>");
        csLog::Log(csLog::Info,
            "    Specify an alert type to resolve.");

        csLog::Log(csLog::Info, "\nList all alerts:");
        csLog::Log(csLog::Info,
            "  -l, --list");

        csLog::Log(csLog::Info, "\nCustom type registration:");
        csLog::Log(csLog::Info,
            "  -R, --register");
        csLog::Log(csLog::Info,
            "    Register a custom alert type.");
        csLog::Log(csLog::Info,
            "  -D, --deregister");
        csLog::Log(csLog::Info,
            "    De-register a custom alert type.");
        csLog::Log(csLog::Info,
            "  -t <type>, --type <type>");
        csLog::Log(csLog::Info,
            "    Specify a custom alert type to register/de-register.");
        csLog::Log(csLog::Info,
            "  -b <basename>, --basename <basename>");
        csLog::Log(csLog::Info,
            "    Specify a custom alert type basename (registration mode only).");

        csLog::Log(csLog::Info, "\nSet alert level override:");
        csLog::Log(csLog::Info,
            "  -S, --set-override");
        csLog::Log(csLog::Info,
            "  -t <type>, --type <type>");
        csLog::Log(csLog::Info,
            "    Specify an alert type override to set.");
        csLog::Log(csLog::Info,
            "  -l <level>, --level <level>");
        csLog::Log(csLog::Info,
            "    Specify an alert level override; NORMal, WARNing, CRITical, or IGNORE.");

        csLog::Log(csLog::Info, "\nClear alert level override:");
        csLog::Log(csLog::Info,
            "  -S, --set-override");
        csLog::Log(csLog::Info,
            "  -t <type>, --type <type>");
        csLog::Log(csLog::Info,
            "    Specify an alert type override to clear.");
    }
    exit(rc);
}

int main(int argc, char *argv[])
{
    int rc;

    int64_t alert_id = 0;
    uint32_t alert_flags = csEventsAlert::csAF_NULL;
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
        { "type", 1, 0, 't' },
        { "level", 1, 0, 'l' },
        { "user", 1, 0, 'u' },
        { "origin", 1, 0, 'o' },
        { "basename", 1, 0, 'b' },
        { "uuid", 1, 0, 'U' },
        { "auto-resolve", 0, 0, 'a' },
        // Mark resolved
        { "mark-resolved", 0, 0, 'r' },
        // List alerts
        { "list", 0, 0, 'L' },
        // Register/deregister type
        { "register", 0, 0, 'R' },
        { "deregister", 0, 0, 'D' },
        // Set alert flags override
        { "set-override", 0, 0, 'S' },
        // Clear alert flags override
        { "clear-override", 0, 0, 'C' },

        { NULL, 0, 0, 0 }
    };

    csLog *log_stdout = new csLog();
    log_stdout->SetMask(csLog::Info | csLog::Warning | csLog::Error);

    conf_filename = strdup("/etc/clearsync.d/csplugin-events.conf");

    for (optind = 1;; ) {
        int o = 0;
        if ((rc = getopt_long(argc, argv,
            "Vc:dh?st:u:U:b:o:rl:LRDSC", options, &o)) == -1) break;
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
        case 'a':
            alert_flags |= csEventsAlert::csAF_FLG_AUTO_RESOLVE;
            break;
        case 'l':
            if (strncasecmp("NORM", optarg, 4) == 0)
                alert_flags |= csEventsAlert::csAF_LVL_NORM;
            else if (strncasecmp("WARN", optarg, 4) == 0)
                alert_flags |= csEventsAlert::csAF_LVL_WARN;
            else if (strncasecmp("CRIT", optarg, 4) == 0)
                alert_flags |= csEventsAlert::csAF_LVL_CRIT;
            else if (strncasecmp("IGNORE", optarg, 4) == 0) 
                alert_flags |= csEventsAlert::csAF_FLG_IGNORE;
            else {
                csLog::Log(csLog::Error, "Invalid alert level specified.");
                exit(1);
            }
            break;
        case 'r':
            mode = csEventsCtl::CTLM_MARK_RESOLVED;
            break;
        case 'L':
            mode = csEventsCtl::CTLM_LIST_ALERTS;
            break;
        case 'R':
            mode = csEventsCtl::CTLM_TYPE_REGISTER;
            break;
        case 'D':
            mode = csEventsCtl::CTLM_TYPE_DEREGISTER;
            break;
        case 'S':
            mode = csEventsCtl::CTLM_OVERRIDE_SET;
            break;
        case 'C':
            mode = csEventsCtl::CTLM_OVERRIDE_CLEAR;
            break;
        }
    }

    csEventsCtl events_ctl;
    csEventsAlert alert;

    if (alert_type == "list") mode = csEventsCtl::CTLM_LIST_TYPES;

    if (mode == csEventsCtl::CTLM_SEND) {
        if (argc > optind) alert_desc << argv[optind];
        for (int i = optind + 1; i < argc; i++) alert_desc << " " << argv[i];
        if (alert_flags == csEventsAlert::csAF_NULL)
            alert_flags |= csEventsAlert::csAF_LVL_NORM;
    }
    else if (mode == csEventsCtl::CTLM_MARK_RESOLVED) {
        if (alert_type.length() == 0) {
            csLog::Log(csLog::Error, "Alert type to mark as resolved is required.");
            exit(1);
        }
    }
    else if (mode == csEventsCtl::CTLM_TYPE_REGISTER) {
        if (alert_type.length() == 0) {
            csLog::Log(csLog::Error, "Alert type to register is required.");
            exit(1);
        }
        if (alert_basename.length() == 0) {
            csLog::Log(csLog::Error, "Alert basename to register is required.");
            exit(1);
        }
    }
    else if (mode == csEventsCtl::CTLM_TYPE_DEREGISTER) {
        if (alert_type.length() == 0) {
            csLog::Log(csLog::Error, "Alert type to de-register is required.");
            exit(1);
        }
    }
    else if (mode == csEventsCtl::CTLM_OVERRIDE_SET) {
        if (alert_type.length() == 0) {
            csLog::Log(csLog::Error, "Alert type to set override for is required.");
            exit(1);
        }
        if (alert_flags == csEventsAlert::csAF_NULL) {
            csLog::Log(csLog::Error, "Alert flags to set override for is required.");
            exit(1);
        }
    }
    else if (mode == csEventsCtl::CTLM_OVERRIDE_CLEAR) {
        if (alert_type.length() == 0) {
            csLog::Log(csLog::Error, "Alert type to clear override for is required.");
            exit(1);
        }
    }

    if (mode == csEventsCtl::CTLM_SEND ||
        mode == csEventsCtl::CTLM_TYPE_REGISTER ||
        mode == csEventsCtl::CTLM_TYPE_DEREGISTER ||
        mode == csEventsCtl::CTLM_OVERRIDE_SET ||
        mode == csEventsCtl::CTLM_OVERRIDE_CLEAR) {

        locale lang;
        for (string::iterator i = alert_type.begin(); i != alert_type.end(); i++) {
            if (!isalpha(*i, lang) && (*i) != '_') {
                csLog::Log(csLog::Error,
                    "Illegal character in alert type; valid characters: A-Z and '_'");
                exit(1);
            }
        }

        transform(
            alert_type.begin(), alert_type.end(), alert_type.begin(),
            ::toupper);
    }

    rc = events_ctl.Exec(
        mode,
        alert_id, alert_flags, alert_type,
        alert_user, alert_origin, alert_basename,
        alert_uuid, alert_desc
    );

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
        int64_t id, uint32_t flags, const string &type, const string &user,
        const string &origin, const string &basename, const string &uuid,
        ostringstream &desc)
{
    csEventsAlert alert;
    csAlertIdMap alert_types;
    csEventsDb_sqlite *events_db;
    vector<csEventsAlert *> result;
    char alert_flags[5];
    struct tm tm_local;
    char date_time[_CS_MAX_TIMESTAMP];
    string alert_type_name, alert_basename, alert_prio;
    uint32_t type_id = 0;

    events_db = new csEventsDb_sqlite(events_conf->GetSqliteDbFilename());

    try {
        events_db->Open();
    } catch (csEventsDbException &e) {
        csLog::Log(csLog::Error, "Database exception: open: %s", e.what());
        throw;
    }
        if (events_conf->InitDb()) events_db->Drop();
    try {
        events_db->Create();
    } catch (csEventsDbException &e) {
        csLog::Log(csLog::Error, "Database exception: create: %s", e.what());
        throw;
    }
    try {
        events_db->SelectTypes(&alert_types);
    } catch (csEventsDbException &e) {
        csLog::Log(csLog::Error, "Database exception: select types: %s", e.what());
        throw;
    }
    try {
        events_conf->MergeRegisteredAlertTypes(alert_types);
    } catch (csEventsDbException &e) {
        csLog::Log(csLog::Error, "Database exception: merge types: %s", e.what());
        throw;
    }

    if (mode == CTLM_SEND || mode == CTLM_MARK_RESOLVED || mode == CTLM_LIST_ALERTS ||
        mode == CTLM_TYPE_REGISTER || mode == CTLM_TYPE_DEREGISTER ||
        mode == CTLM_OVERRIDE_SET || mode == CTLM_OVERRIDE_CLEAR) {

        events_socket = new csEventsSocketClient(events_conf->GetEventsSocketPath());
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

        case CTLM_MARK_RESOLVED:
            alert.SetType(events_conf->GetAlertId(type));

            events_socket->AlertMarkAsResolved(alert);

            break;

        case CTLM_LIST_TYPES:
            csLog::Log(csLog::Info, "Alert Types:");
            events_conf->GetAlertTypes(alert_types);
            for (csAlertIdMap::iterator i = alert_types.begin();
                i != alert_types.end(); i++) {
                csLog::Log(csLog::Info, "  %s", i->second.c_str());
            }
            break;

        case CTLM_LIST_ALERTS:
            events_socket->AlertSelect("ORDER BY stamp", result);
            if (result.size() == 0) {
                csLog::Log(csLog::Info, "No alerts in database.");
                break;
            }
            for (vector<csEventsAlert *>::iterator i = result.begin();
                i != result.end(); i++) {

                const time_t stamp = (*i)->GetUpdated();
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

                alert_flags[0] = ((*i)->GetFlags() &
                    csEventsAlert::csAF_FLG_NOTIFIED) ? 'n' : '-';
                alert_flags[1] = ((*i)->GetFlags() &
                    csEventsAlert::csAF_FLG_RESOLVED) ? 'r' : '-';
                alert_flags[2] = ((*i)->GetFlags() &
                    csEventsAlert::csAF_FLG_AUTO_RESOLVE) ? 'a' : '-';
                alert_flags[3] = ((*i)->GetFlags() &
                    csEventsAlert::csAF_FLG_IGNORE) ? 'i' : '-';
                alert_flags[4] = '\0';

                csLog::Log(csLog::Info, "#%-10llu%-30s%s%s[%s] %s",
                    (*i)->GetId(), date_time, alert_prio.c_str(),
                    (alert_prio.length()) ? ": " : " ",
                    alert_flags, alert_type_name.c_str());
                csLog::Log(csLog::Info, (*i)->GetDescription().c_str());
                csLog::Log(csLog::Info, "");
            }
            break;
            
        case CTLM_TYPE_REGISTER:
            alert_type_name = type;
            alert_basename = basename;
            events_socket->TypeRegister(alert_type_name, alert_basename);
            break;

        case CTLM_TYPE_DEREGISTER:
            alert_type_name = type;
            events_socket->TypeDeregister(alert_type_name);
            break;

        case CTLM_OVERRIDE_SET:
        case CTLM_OVERRIDE_CLEAR:
            try {
                type_id = events_conf->GetAlertId(type);
            } catch (csException &e) {
                csLog::Log(csLog::Error, "Unknown alert type: %s",
                    type.c_str());
                exit(1);
            }

            if (mode == CTLM_OVERRIDE_SET)
                events_socket->OverrideSet(type_id, flags);
            else if (mode == CTLM_OVERRIDE_CLEAR)
                events_socket->OverrideClear(type_id);

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
