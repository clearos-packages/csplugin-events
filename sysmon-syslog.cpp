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

#include <unistd.h>
#include <fcntl.h>
#include <linux/un.h>

#include <clearsync/csplugin.h>
#include <clearsync/csselect.h>

#include "sysmon-syslog.h"

csSysMonSyslog::csSysMonSyslog(csEventClient *parent, const string &socket_path)
    : parent(parent), cs_select(NULL), rx_bufsize(0), buffer(NULL)
{
    if ((sd = socket(PF_LOCAL, SOCK_DGRAM, 0)) < 0)
        throw csException(errno, "socket");

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(struct sockaddr_un));

    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path, socket_path.c_str(), UNIX_PATH_MAX);

//    int sd_enable = 1;
//    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &sd_enable, sizeof(int)) < 0)
//        throw csException(errno, "setsockopt(SO_REUSEADDR)");
    unlink(socket_path.c_str());

    if (bind(sd, (struct sockaddr *)&sa, sizeof(struct sockaddr_un)) != 0)
        throw csException(errno, "bind");

    int sd_flags = fcntl(sd, F_GETFL, 0);
    if (sd_flags == -1) throw csException(errno, "fcntl(F_GETFL)");
    if (fcntl(sd, F_SETFL, sd_flags | O_NONBLOCK) < 0)
        throw csException(errno, "fcntl(F_SETFL)");

    cs_select = new csSelect(parent);
    cs_select->Set(sd, csSelect::FDS_READ);

    socklen_t opt_len = sizeof(size_t);
    if (getsockopt(sd, SOL_SOCKET, SO_RCVBUF, (void *)&rx_bufsize, &opt_len) != 0)
        throw csException(errno, "getsockopt(SO_RCVBUF)");

    csLog::Log(csLog::Debug, "SO_RCVBUF: %ld", rx_bufsize);

    buffer = new char[++rx_bufsize];
    if (buffer == NULL) throw csException(ENOMEM, "buffer");
}

csSysMonSyslog::~csSysMonSyslog()
{
    if (sd >= 0 && cs_select != NULL) {
        delete cs_select;
        close(sd);
    }

    if (buffer != NULL) delete [] buffer;
}

void csSysMonSyslog::Read(vector<string> &messages)
{
    if (!cs_select->IsSet(sd, csSelect::FDS_READ)) {
        csLog::Log(csLog::Debug, "Descriptor not set for read: %d", sd);
        return;
    }

    cs_select->Pause();

    for ( ;; ) {
        memset(buffer, 0, rx_bufsize);
        ssize_t bytes = read(sd, (void *)buffer, rx_bufsize);
        if (bytes < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                csLog::Log(csLog::Error,
                    "Error reading syslog packet: %s", strerror(errno));
            }
            break;
        }
        else if (bytes == 0) {
            csLog::Log(csLog::Debug, "Nothing to read on descriptor: %d", sd);
            break;
        }

        messages.push_back(buffer);
    }

    cs_select->Resume();
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
