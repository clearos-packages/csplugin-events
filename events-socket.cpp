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

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/un.h>

#include <sstream>

#include <sqlite3.h>
#include <openssl/sha.h>

#include "events-alert.h"
#include "events-db.h"
#include "events-socket.h"

csEventsSocket::csEventsSocket(const string &socket_path)
    : socket_path(socket_path), page_size(0), buffer(NULL),
    buffer_pages(0), buffer_length(0), header(NULL), payload(NULL),
    payload_index(NULL), proto_version(0)
{
    if ((sd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
        throw csEventsSocketException(errno, "Create socket");

    Create();
}

csEventsSocket::csEventsSocket(int sd, const string &socket_path)
    : sd(sd), socket_path(socket_path), page_size(0), buffer(NULL),
    buffer_pages(0), buffer_length(0), header(NULL), payload(NULL),
    payload_index(NULL), proto_version(0)
{
    Create();
}

void csEventsSocket::Create(void)
{
    memset(&sa, 0, sizeof(struct sockaddr_un));

    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path, socket_path.c_str(), UNIX_PATH_MAX);

    int sd_flags = fcntl(sd, F_GETFL, 0);
    if (sd_flags == -1) throw csEventsSocketException(errno, "Get socket flags");
    if (fcntl(sd, F_SETFL, sd_flags | O_NONBLOCK) < 0)
        throw csEventsSocketException(errno, "Set non-blocking socket mode");

    page_size = ::csGetPageSize();
    AllocatePayloadBuffer(page_size);

    ResetPacket();
}

csEventsSocket::~csEventsSocket()
{
    if (sd > -1) close(sd);
    if (buffer != NULL) free(buffer);
}

void csEventsSocket::AllocatePayloadBuffer(ssize_t length)
{
    ssize_t buffer_needed = length + sizeof(csEventsHeader);

    while (buffer_length < buffer_needed) {
        buffer_pages++;
        buffer_length = buffer_pages * page_size;

        buffer = (uint8_t *)realloc(buffer, buffer_length);

        if (buffer == NULL)
            throw csEventsSocketException(errno, "Out of memory");
    }

    header = (csEventsHeader *)buffer;
    payload = buffer + sizeof(csEventsHeader);
}

csEventsOpCode csEventsSocket::ReadPacket(void)
{
    ResetPacket();

    ssize_t bytes = Read((uint8_t *)header, sizeof(csEventsHeader));
    if (bytes > 0) {
//        fprintf(stderr, "Read packet header:\n");
//        ::csHexDump(stderr, (const void *)header, sizeof(csEventsHeader));
        if (header->payload_length > 0) {
            if ((bytes = Read(payload, header->payload_length)) > 0) {
//                fprintf(stderr, "Read packet payload:\n");
//                ::csHexDump(
//                    stderr, (const void *)payload, header->payload_length
//                );
            }
        }
    }

    return (csEventsOpCode)header->opcode;
}

void csEventsSocket::WritePacket(csEventsOpCode opcode)
{
    header->opcode = (uint8_t)opcode;
    ssize_t bytes = Write(buffer,
        sizeof(csEventsHeader) + header->payload_length);
    if (bytes > 0) {
//        fprintf(stderr, "Wrote packet header:\n");
//        ::csHexDump(stderr, (const void *)header, sizeof(csEventsHeader));
        if (header->payload_length > 0) {
//            fprintf(stderr, "Wrote packet payload:\n");
//            ::csHexDump(
//                stderr, (const void *)payload, header->payload_length
//            );
        }
    }
}

void csEventsSocket::ReadPacketVar(string &v)
{
    uint8_t length;
    uint8_t *ptr = payload_index;
    memcpy((void *)&length, (const void *)ptr, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    if (length > 0) {
        v.assign((const char *)ptr, (size_t)length);
        ptr += length;
    }
    else v.clear();

    payload_index = ptr;
}

void csEventsSocket::ReadPacketVar(csEventsAlert &alert)
{
    csEventsAlert::csEventsAlertData data;

    ReadPacketVar((void *)&data.id, sizeof(int64_t));
    uint32_t stamp;
    ReadPacketVar((void *)&stamp, sizeof(uint32_t));
    data.stamp = (time_t)stamp;
    ReadPacketVar((void *)&data.flags, sizeof(uint32_t));
    ReadPacketVar((void *)&data.type, sizeof(uint32_t));
    ReadPacketVar((void *)&data.user, sizeof(uint32_t));

    gid_t gid;
    uint8_t groups;
    ReadPacketVar((void *)&groups, sizeof(uint8_t));

    for (uint8_t i = 0; i < groups; i++) {
        ReadPacketVar((void *)&gid, sizeof(uint32_t));
        data.groups.push_back(gid);
    }

    ReadPacketVar(data.origin);
    ReadPacketVar(data.basename);
    ReadPacketVar(data.uuid);
    ReadPacketVar(data.desc);

    alert.SetData(data);
}

void csEventsSocket::ReadPacketVar(void *v, size_t length)
{
    uint8_t *ptr = payload_index;
    memcpy(v, (const void *)ptr, length);
    ptr += length;

    payload_index = ptr;
}

void csEventsSocket::WritePacketVar(const string &v)
{
    uint8_t length = (uint8_t)v.length();
    header->payload_length += v.length() + sizeof(uint8_t);

    AllocatePayloadBuffer(header->payload_length);

    uint8_t *ptr = payload_index;
    memcpy((void *)ptr, (const void *)&length, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    if (length > 0) {
        memcpy((void *)ptr, (const void *)v.c_str(), v.length());
        ptr += v.length();
    }

    payload_index = ptr;
}

void csEventsSocket::WritePacketVar(const csEventsAlert &alert)
{
    const csEventsAlert::csEventsAlertData *data = alert.GetDataPtr();

    WritePacketVar((const void *)&data->id, sizeof(int64_t));
    uint32_t stamp = (uint32_t)data->stamp;
    WritePacketVar((const void *)&stamp, sizeof(uint32_t));
    WritePacketVar((const void *)&data->flags, sizeof(uint32_t));
    WritePacketVar((const void *)&data->type, sizeof(uint32_t));
    WritePacketVar((const void *)&data->user, sizeof(uint32_t));

    uint8_t groups = (uint8_t)data->groups.size();
    WritePacketVar((const void *)&groups, sizeof(uint8_t));

    vector<gid_t>::const_iterator i;
    for (i = data->groups.begin(); i != data->groups.end(); i++)
        WritePacketVar((const void *)&(*i), sizeof(uint32_t));

    WritePacketVar(data->origin);
    WritePacketVar(data->basename);
    WritePacketVar(data->uuid);
    WritePacketVar(data->desc);
}

void csEventsSocket::WritePacketVar(const void *v, size_t length)
{
    header->payload_length += length;

    AllocatePayloadBuffer(header->payload_length);

    uint8_t *ptr = payload_index;
    memcpy((void *)ptr, v, length);
    ptr += length;

    payload_index = ptr;
}

csEventsProtoResult csEventsSocket::VersionExchange(void)
{
    csEventsProtoResult result = csSMPR_OK;

    if (mode == csSM_CLIENT) {
        ResetPacket();

        proto_version = _EVENTS_SOCKET_PROTOVER;
        WritePacketVar((void *)&proto_version, sizeof(uint32_t));
        WritePacket(csSMOC_VERSION);

        return ReadResult();
    }
    else if (mode == csSM_SERVER) {
        ReadPacket();

        if (header->opcode != csSMOC_VERSION) {
            throw csEventsSocketProtocolException(sd,
                "Unexpected protocol op-code");
        }

        if (header->payload_length != sizeof(uint32_t)) {
            throw csEventsSocketProtocolException(sd,
                "Invalid protocol version length");
        }

        uint32_t client_proto_version;

        ReadPacketVar((void *)&client_proto_version, sizeof(uint32_t));

        if (client_proto_version > _EVENTS_SOCKET_PROTOVER) {
            WriteResult(csSMPR_VERSION_MISMATCH);
            throw csEventsSocketProtocolException(sd,
                "Unsupported protocol version");
        }

        proto_version = client_proto_version;

        WriteResult(result);
    }

    return result;
}

void csEventsSocket::AlertInsert(csEventsAlert &alert)
{
    if (mode == csSM_CLIENT) {
        ResetPacket();
        WritePacketVar(alert);
        WritePacket(csSMOC_ALERT_INSERT);
    }
    else if (mode == csSM_SERVER) {
        ReadPacketVar(alert);
        alert.SetStamp();
    }
}

uint32_t csEventsSocket::AlertSelect(
    const string &where, vector<csEventsAlert *> &result)
{
    uint32_t matches = 0;

    ResetPacket();
    WritePacketVar(where);
    WritePacket(csSMOC_ALERT_SELECT);

    if (ReadResult() != csSMPR_ALERT_MATCHES)
        throw csEventsSocketProtocolException(sd, "Unexpected result");

    ReadPacketVar((void *)&matches, sizeof(uint32_t));

    csLog::Log(csLog::Debug, "Select alert matches: %u", matches);

    for (uint32_t i = 0; i < matches; i++) {
        if (ReadPacket() != csSMOC_ALERT_RECORD) {
            throw csEventsSocketProtocolException(sd,
                "Unexpected protocol op-code");
        }

        csEventsAlert *alert = new csEventsAlert();
        ReadPacketVar(*alert);
        result.push_back(alert);
    }

    return matches;
}

void csEventsSocket::AlertSelect(csEventsDb *db)
{
    string where;
    ReadPacketVar(where);

    size_t eol = where.find_first_of(';');
    if (eol != string::npos) where.resize(eol);
    if (where.length() < 4)
        throw csEventsSocketProtocolException(sd, "Invalid where clause");

    vector<csEventsAlert *> result;

    try {
        uint32_t matches = db->SelectAlert(where, &result);

        WriteResult(csSMPR_ALERT_MATCHES, &matches, sizeof(uint32_t));

        for (vector<csEventsAlert *>::iterator i = result.begin();
            i != result.end(); i++) {
            ResetPacket();
            WritePacketVar(*(*i));
            WritePacket(csSMOC_ALERT_RECORD);
        }
    } catch (csException &e) {
        for (vector<csEventsAlert *>::iterator i = result.begin();
            i != result.end(); i++) delete (*i);
        throw;
    }
}

void csEventsSocket::AlertMarkAsRead(csEventsAlert &alert)
{
    int64_t id;

    if (mode == csSM_CLIENT) {
        id = alert.GetId();

        ResetPacket();
        WritePacketVar((const void *)&id, sizeof(int64_t));
        WritePacket(csSMOC_ALERT_MARK_AS_READ);
    }
    else if (mode == csSM_SERVER) {
        ReadPacketVar((void *)&id, sizeof(int64_t));
        alert.SetId(id);
    }
}

csEventsProtoResult csEventsSocket::ReadResult(void)
{
    ReadPacket();

    if (header->opcode != csSMOC_RESULT) {
        throw csEventsSocketProtocolException(sd,
            "Unexpected protocol op-code");
    }

    if (header->payload_length < sizeof(uint8_t)) {
        throw csEventsSocketProtocolException(sd,
            "Invalid protocol result length");
    }

    uint8_t rc;
    ReadPacketVar((void *)&rc, sizeof(uint8_t));

    return (csEventsProtoResult)rc;
}

void csEventsSocket::WriteResult(csEventsProtoResult result,
    const void *data, uint32_t length)
{
    ResetPacket();

    uint8_t rc = (uint8_t)result;
    header->payload_length = sizeof(uint8_t);

    memcpy((void *)payload, (const void *)&rc, sizeof(uint8_t));

    if (data != NULL && length > 0) {
        header->payload_length += length;
        memcpy((void *)(payload + sizeof(uint8_t)), data, length);
    }

    WritePacket(csSMOC_RESULT);
}

ssize_t csEventsSocket::Read(uint8_t *data, ssize_t length, time_t timeout)
{
    struct timeval tv, tv_active;
    uint8_t *ptr = data;
    ssize_t bytes_read, bytes_left = length;

    gettimeofday(&tv_active, NULL);

    while (bytes_left > 0) {
        bytes_read = recv(sd, (char *)ptr, bytes_left, 0);

        if (!bytes_read) throw csEventsSocketHangupException(sd);
        else if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                gettimeofday(&tv, NULL);
                if (tv.tv_sec - tv_active.tv_sec <= timeout) {
                    usleep(csSocketRetry);
                    continue;
                }
                throw csEventsSocketTimeoutException(sd);
            }
            throw csEventsSocketException(errno, "recv", sd);
        }

        ptr += bytes_read;
        bytes_left -= bytes_read;

        gettimeofday(&tv_active, NULL);
    }

    return bytes_read;
}

ssize_t csEventsSocket::Write(const uint8_t *data, ssize_t length, time_t timeout)
{
    struct timeval tv, tv_active;
    const uint8_t *ptr = data;
    ssize_t bytes_wrote;
    ssize_t bytes_left = length;

    gettimeofday(&tv_active, NULL);

    while (bytes_left > 0) {
        bytes_wrote = send(sd, (const char *)ptr, bytes_left, 0);

        if (!bytes_wrote) throw csEventsSocketHangupException(sd);
        else if (bytes_wrote < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                gettimeofday(&tv, NULL);
                if (tv.tv_sec - tv_active.tv_sec <= timeout) {
                    usleep(csSocketRetry);
                    continue;
                }
                throw csEventsSocketTimeoutException(sd);
            }
            throw csEventsSocketException(errno, "send", sd);
        }

        ptr += bytes_wrote;
        bytes_left -= bytes_wrote;

        gettimeofday(&tv_active, NULL);
    }

    return bytes_wrote;
}

csEventsSocketClient::csEventsSocketClient(const string &socket_path)
    : csEventsSocket(socket_path)
{
    mode = csSM_CLIENT;
}

csEventsSocketClient::csEventsSocketClient(int sd, const string &socket_path)
    : csEventsSocket(sd, socket_path)
{
    mode = csSM_SERVER;
}

void csEventsSocketClient::Connect(int timeout)
{
    int rc, attempts = 0;
    do {
        rc = connect(sd, (const struct sockaddr *)&sa, sizeof(struct sockaddr_un));
        if (rc == 0) break;
        sleep(1);
    }
    while ((errno == EAGAIN || errno == EWOULDBLOCK) && ++attempts != timeout);

    if (rc != 0) throw csEventsSocketException(errno, "Socket connect");

    csLog::Log(csLog::Debug, "Events client connected to: %s",
        socket_path.c_str());
}

csEventsSocketServer::csEventsSocketServer(const string &socket_path)
    : csEventsSocket(socket_path)
{
    unlink(socket_path.c_str());

    if (bind(sd, (struct sockaddr *)&sa, sizeof(struct sockaddr_un)) != 0)
        throw csEventsSocketException(errno, "Binding socket");
    if (listen(sd, SOMAXCONN) != 0)
        throw csEventsSocketException(errno, "Listening on socket");
}

csEventsSocketClient *csEventsSocketServer::Accept(void)
{
    int client_sd;
    struct sockaddr_un sa_client;
    socklen_t sa_len = sizeof(struct sockaddr_un);
    if ((client_sd = accept(sd, (struct sockaddr *)&sa_client, &sa_len)) < 0)
        throw csEventsSocketException(errno, "Accepting client connection");

    csLog::Log(csLog::Debug, "Events client connection accepted: %d", client_sd);

    return new csEventsSocketClient(client_sd, socket_path);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
