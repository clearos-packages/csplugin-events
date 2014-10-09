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

#include <sstream>

#include <sqlite3.h>

#include "sysmon-conf.h"
#include "sysmon-alert.h"
#include "sysmon-alert-source.h"
#include "sysmon-db.h"
#include "sysmon-syslog.h"
#include "csplugin-sysmon.h"

int main(int argc, char *argv[])
{
    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
