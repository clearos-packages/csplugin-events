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

#ifndef _SYSMONCTL_H
#define _SYSMONCTL_H

class csSysMonCtl : public csEventClient
{
public:
    enum csSysMonCtlMode
    {
        CTLM_NULL,
        CTLM_SEND,
        CTLM_LIST_TYPES,
        CTLM_MARK_AS_READ,
        CTLM_LIST_ALERTS,
    };

    csSysMonCtl();
    virtual ~csSysMonCtl();

    int Exec(csSysMonCtlMode mode,
        int64_t id, uint32_t flags, const string &type,
        const string &user, const string &uuid, const string &icon,
        ostringstream &desc);

protected:
    friend class csPluginXmlParser;

    csSysMonConf *sysmon_conf;
    csSysMonSocketClient *sysmon_socket;
};

#endif // _CSPLUGIN_SYSMON_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
