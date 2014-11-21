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

#include <pwd.h>

#include "sysmon-alert.h"

csSysMonAlert::csSysMonAlert()
{
    Reset();
    SetStamp();
}

csSysMonAlert::csSysMonAlert(
    uint32_t id, uint32_t flags, uint32_t type,
    const string &uuid, const string &icon, const string &desc)
{
    Reset();
    SetStamp();

    data.id = id;
    data.flags = flags;
    data.type = type;
    data.uuid = uuid;
    data.icon = icon;
    data.desc = desc;
}

csSysMonAlert::~csSysMonAlert()
{
}

void csSysMonAlert::Reset(void)
{
    data.id = 0;
    data.stamp = 0;
    data.flags = csAF_NULL;
    data.type = csAT_NULL;
    data.user = 0;
    data.groups.clear();
    data.uuid.clear();
    data.icon.clear();
    data.desc.clear();
}

void csSysMonAlert::AddGroup(gid_t gid)
{
    bool found = false;
    for (vector<gid_t>::iterator i = data.groups.begin();
        i != data.groups.end(); i++) {
        if ((*i) != gid) continue;
        found = true;
        break;
    }

    if (!found) data.groups.push_back(gid);
}

void csSysMonAlert::GetGroups(vector<gid_t> &groups)
{
    groups.clear();
    for (vector<gid_t>::iterator i = data.groups.begin();
        i != data.groups.end(); i++) {
        groups.push_back((*i));
    }
}

void csSysMonAlert::SetData(const csSysMonAlertData &data)
{
    SetId(data.id);
    SetStamp(data.stamp);
    SetFlags(data.flags);
    SetType(data.type);
    SetUser(data.user);

    for (vector<gid_t>::const_iterator i = data.groups.begin();
        i != data.groups.end(); i++) AddGroup((*i));

    SetUUID(data.uuid);
    SetIcon(data.icon);
    SetDescription(data.desc);
}

void csSysMonAlert::SetUser(const string &user)
{
    struct passwd *pwent = NULL;

    pwent = getpwnam(user.c_str());
    if (pwent == NULL)
        throw csException(ENOENT, "User not found");
    data.user = pwent->pw_uid;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
