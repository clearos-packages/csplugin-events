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

#include "sysmon-alert.h"

csSysMonAlert::csSysMonAlert()
    : id(0), stamp(0), flags(csAF_NULL), type(csAT_NULL)
{
    SetStamp();
}

csSysMonAlert::~csSysMonAlert()
{
}

void csSysMonAlert::AddGroup(gid_t gid)
{
    bool found = false;
    for (vector<gid_t>::iterator i = groups.begin(); i != groups.end(); i++) {
        if ((*i) != gid) continue;
        found = true;
        break;
    }

    if (!found) groups.push_back(gid);
}

void csSysMonAlert::GetGroups(vector<gid_t> &groups)
{
    groups.clear();
    for (vector<gid_t>::iterator i = this->groups.begin(); i != groups.end(); i++) {
        groups.push_back((*i));
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
