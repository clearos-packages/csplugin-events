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

#ifndef _EVENTSCTL_H
#define _EVENTSCTL_H

class csEventsCtl : public csEventClient
{
public:
    enum csEventsCtlMode
    {
        CTLM_NULL,
        CTLM_SEND,
        CTLM_LIST_TYPES,
        CTLM_LIST_ALERTS,
        CTLM_MARK_RESOLVED,
        CTLM_TYPE_REGISTER,
        CTLM_TYPE_DEREGISTER,
    };

    csEventsCtl();
    virtual ~csEventsCtl();

    int Exec(csEventsCtlMode mode,
        int64_t id, uint32_t flags, const string &type,
        const string &user, const string &origin, const string &basename,
        const string &uuid, ostringstream &desc);

protected:
    friend class csPluginXmlParser;

    csEventsConf *events_conf;
    csEventsSocketClient *events_socket;
};

#endif // _CSPLUGIN_EVENTS_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
