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
#include <clearsync/csselect.h>

#include <iostream>
#include <sstream>

#include <unistd.h>
#include <getopt.h>
#include <sqlite3.h>

#include "sysmon-conf.h"
#include "sysmon-alert.h"
#include "sysmon-alert-source.h"
#include "sysmon-db.h"
#include "sysmon-socket.h"
#include "sysmon-syslog.h"
#include "csplugin-sysmon.h"
#include "sysmonctl.h"

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

        csLog::Log(csLog::Info, "\nSend an Alert:");
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
            "  -i <icon>, --icon <icon>");
        csLog::Log(csLog::Info,
            "    Specify an optional icon.");
    }
    exit(rc);
}

int main(int argc, char *argv[])
{
    int rc;

    uint32_t alert_flags = csSysMonAlert::csAF_NULL;
    string alert_type, alert_user, alert_uuid, alert_icon;
    ostringstream alert_desc;

    csSysMonCtl::csSysMonCtlMode mode = csSysMonCtl::CTLM_NULL;

    static struct option options[] =
    {
        { "version", 0, 0, 'V' },
        { "config", 1, 0, 'c' },
        { "debug", 0, 0, 'd' },
        { "help", 0, 0, 'h' },
        // Send an alert
        { "send", 0, 0, 's' },
        { "persistent", 0, 0, 'p' },
        { "type", 0, 0, 't' },
        { "user", 0, 0, 'u' },
        { "uuid", 0, 0, 'U' },
        { "icon", 0, 0, 'i' },

        { NULL, 0, 0, 0 }
    };

    csLog *log_stdout = new csLog();
    log_stdout->SetMask(csLog::Info | csLog::Warning | csLog::Error);

    conf_filename = strdup("/etc/clearsync.d/csplugin-sysmon.conf");

    for (optind = 1;; ) {
        int o = 0;
        if ((rc = getopt_long(argc, argv,
            "Vc:dh?spt:u:U:i:", options, &o)) == -1) break;
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
            if (mode != csSysMonCtl::CTLM_NULL) usage(1);
            mode = csSysMonCtl::CTLM_SEND;
            break;
        case 'p':
            alert_flags |= csSysMonAlert::csAF_FLG_PERSIST;
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
        case 'i':
            alert_icon = optarg;
            break;
        }
    }

    csSysMonCtl sysmon_ctl;
    csSysMonAlert alert;

    if (alert_type == "list") mode = csSysMonCtl::CTLM_LIST_TYPES;

    if (mode == csSysMonCtl::CTLM_SEND) {
        if (argc > optind) alert_desc << argv[optind];
        for (int i = optind + 1; i < argc; i++) alert_desc << " " << argv[i];
    }

    sysmon_ctl.Exec(mode,
        alert_flags, alert_type, alert_user, alert_uuid, alert_icon, alert_desc);

    free(conf_filename);

    return 0;
}

csSysMonCtl::csSysMonCtl()
{
    csPluginXmlParser *parser = new csPluginXmlParser();
    sysmon_conf = new csSysMonConf(NULL, conf_filename, parser);
    parser->SetConf(dynamic_cast<csConf *>(sysmon_conf));
    sysmon_conf->Reload();
}

csSysMonCtl::~csSysMonCtl()
{
    if (sysmon_conf) delete sysmon_conf;
}

void csSysMonCtl::Exec(csSysMonCtlMode &mode, uint32_t &flags, const string &type,
        const string &user, const string &uuid, const string &icon,
        ostringstream &desc)
{
    csSysMonAlert alert;
    uint32_t alert_type = 0;
    csAlertIdMap alert_types;

    try {
        switch (mode) {
        case CTLM_SEND:
            alert.SetFlags(flags);
            alert.SetType(sysmon_conf->GetAlertId(type));
            if (user.length()) alert.SetUser(user);
            else alert.SetUser(geteuid());
            if (uuid.length()) alert.SetUUID(uuid);
            if (icon.length()) alert.SetIcon(icon);
            if (desc.tellp()) alert.SetDescription(desc.str());
            break;
        case CTLM_LIST_TYPES:
            csLog::Log(csLog::Info, "Alert Types:");
            sysmon_conf->GetAlertTypes(alert_types);
            for (csAlertIdMap::iterator i = alert_types.begin(); i != alert_types.end(); i++)
                csLog::Log(csLog::Info, "  %s", i->second.c_str());
            break;
        };
    } catch (csException &e) {
        csLog::Log(csLog::Error, "Exception: %s", e.estring.c_str());
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
