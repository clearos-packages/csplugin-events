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

#include "sysmon-alert.h"
#include "sysmon-socket.h"

csSysMonSocket::csSysMonSocket(const string &socket_path)
    : socket_path(socket_path), page_size(0), buffer(NULL),
    buffer_pages(0), buffer_length(0), header(NULL), payload(NULL),
    payload_index(NULL), proto_version(0)
{
    if ((sd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
        throw csSysMonSocketException(errno, "Create socket");

    Create();
}

csSysMonSocket::csSysMonSocket(int sd, const string &socket_path)
    : sd(sd), socket_path(socket_path), page_size(0), buffer(NULL),
    buffer_pages(0), buffer_length(0), header(NULL), payload(NULL),
    payload_index(NULL), proto_version(0)
{
    Create();
}

void csSysMonSocket::Create(void)
{
    memset(&sa, 0, sizeof(struct sockaddr_un));

    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path, socket_path.c_str(), UNIX_PATH_MAX);

    int sd_flags = fcntl(sd, F_GETFL, 0);
    if (sd_flags == -1) throw csSysMonSocketException(errno, "Get socket flags");
    if (fcntl(sd, F_SETFL, sd_flags | O_NONBLOCK) < 0)
        throw csSysMonSocketException(errno, "Set non-blocking socket mode");

    page_size = ::csGetPageSize();
    AllocatePayloadBuffer(page_size);

    ResetPacket();
}

csSysMonSocket::~csSysMonSocket()
{
    if (sd > -1) close(sd);
    if (buffer != NULL) free(buffer);
}

void csSysMonSocket::AllocatePayloadBuffer(ssize_t length)
{
    ssize_t buffer_needed = length + sizeof(csSysMonHeader);

    while (buffer_length < buffer_needed) {
        buffer_pages++;
        buffer_length = buffer_pages * page_size;

        buffer = (uint8_t *)realloc(buffer, buffer_length);

        if (buffer == NULL)
            throw csSysMonSocketException(errno, "Out of memory");
    }

    header = (csSysMonHeader *)buffer;
    payload = buffer + sizeof(csSysMonHeader);
}

csSysMonOpCode csSysMonSocket::ReadPacket(void)
{
    ResetPacket();

    ssize_t bytes = Read((uint8_t *)header, sizeof(csSysMonHeader));
    if (bytes > 0 && header->payload_length > 0)
        bytes = Read(payload, header->payload_length);
    
    return (csSysMonOpCode)header->opcode;
}

void csSysMonSocket::WritePacket(csSysMonOpCode opcode)
{
    header->opcode = (uint8_t)opcode;
    ssize_t bytes = Write(buffer,
        sizeof(csSysMonHeader) + header->payload_length);
}

void csSysMonSocket::ReadPacketVar(string &v)
{
    uint32_t length;
    uint8_t *ptr = payload_index;
    memcpy((void *)&length, (const void *)ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    if (length > 0) {
        v.assign((const char *)ptr, (size_t)length);
        ptr += length;
    }
    else v.clear();

    payload_index = ptr;
}

void csSysMonSocket::ReadPacketVar(csSysMonAlert &alert)
{
    csSysMonAlert::csSysMonAlertData data;

    ReadPacketVar((void *)&data.id, sizeof(int64_t));
    ReadPacketVar((void *)&data.stamp, sizeof(uint32_t));
    ReadPacketVar((void *)&data.flags, sizeof(uint32_t));
    ReadPacketVar((void *)&data.type, sizeof(uint32_t));
    ReadPacketVar((void *)&data.user, sizeof(uint32_t));

    gid_t gid;
    uint32_t groups;
    ReadPacketVar((void *)&groups, sizeof(uint32_t));

    for (uint32_t i = 0; i < groups; i++) {
        ReadPacketVar((void *)&gid, sizeof(uint32_t));
        data.groups.push_back(gid);
    }

    ReadPacketVar(data.uuid);
    ReadPacketVar(data.icon);
    ReadPacketVar(data.desc);

    alert.SetData(data);
}

void csSysMonSocket::ReadPacketVar(void *v, size_t length)
{
    uint8_t *ptr = payload_index;
    memcpy(v, (const void *)ptr, length);
    ptr += length;

    payload_index = ptr;
}

void csSysMonSocket::WritePacketVar(const string &v)
{
    uint32_t length = (uint32_t)v.length();
    header->payload_length += v.length() + sizeof(uint32_t);

    AllocatePayloadBuffer(header->payload_length);

    uint8_t *ptr = payload_index;
    memcpy((void *)ptr, (const void *)&length, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    if (length > 0) {
        memcpy((void *)ptr, (const void *)v.c_str(), v.length());
        ptr += v.length();
    }

    payload_index = ptr;
}

void csSysMonSocket::WritePacketVar(const csSysMonAlert &alert)
{
    const csSysMonAlert::csSysMonAlertData *data = alert.GetDataPtr();

    WritePacketVar((const void *)&data->id, sizeof(data->id));
    WritePacketVar((const void *)&data->stamp, sizeof(data->stamp));
    WritePacketVar((const void *)&data->flags, sizeof(data->flags));
    WritePacketVar((const void *)&data->type, sizeof(data->type));
    WritePacketVar((const void *)&data->user, sizeof(data->user));

    uint32_t groups = data->groups.size();
    WritePacketVar((const void *)&groups, sizeof(uint32_t));

    vector<gid_t>::const_iterator i;
    for (i = data->groups.begin(); i != data->groups.end(); i++)
        WritePacketVar((const void *)&(*i), sizeof(gid_t));

    WritePacketVar(data->uuid);
    WritePacketVar(data->icon);
    WritePacketVar(data->desc);
}

void csSysMonSocket::WritePacketVar(const void *v, size_t length)
{
    header->payload_length += length;

    AllocatePayloadBuffer(header->payload_length);

    uint8_t *ptr = payload_index;
    memcpy((void *)ptr, v, length);
    ptr += length;

    payload_index = ptr;
}

void csSysMonSocket::VersionExchange(bool read_version)
{
    if (read_version) {
        ReadPacket();

        if (header->opcode != csSMOC_VERSION) {
            throw csSysMonSocketProtocolException(sd,
                "Unexpected protocol op-code");
        }

        if (header->payload_length != sizeof(uint32_t)) {
            throw csSysMonSocketProtocolException(sd,
                "Invalid protocol version length");
        }

        uint32_t client_proto_version;

        ReadPacketVar((void *)&client_proto_version, sizeof(uint32_t));

        if (client_proto_version > _SYSMON_SOCKET_PROTOVER) {
            WriteResult(csSMPR_VERSION_MISMATCH);
            throw csSysMonSocketProtocolException(sd,
                "Unsupported protocol version");
        }

        proto_version = client_proto_version;
    }
    else {
        ResetPacket();

        proto_version = _SYSMON_SOCKET_PROTOVER;
        WritePacketVar((void *)&proto_version, sizeof(uint32_t));
        WritePacket(csSMOC_VERSION);
    }
}

csSysMonProtoResult csSysMonSocket::ReadResult(void)
{
    ReadPacket();

    if (header->opcode != csSMOC_RESULT) {
        throw csSysMonSocketProtocolException(sd,
            "Unexpected protocol op-code");
    }

    if (header->payload_length != sizeof(uint32_t)) {
        throw csSysMonSocketProtocolException(sd,
            "Invalid protocol result length");
    }

    uint32_t rc;
    ReadPacketVar((void *)&rc, header->payload_length);

    return (csSysMonProtoResult)rc;
}

void csSysMonSocket::WriteResult(csSysMonProtoResult result)
{
    ResetPacket();

    uint32_t rc = (uint32_t)result;
    header->payload_length = sizeof(uint32_t);

    memcpy((void *)payload, (const void *)&rc, sizeof(uint32_t));

    WritePacket(csSMOC_RESULT);
}

void csSysMonSocket::AlertInsert(const csSysMonAlert &alert)
{
}

void csSysMonSocket::AlertSelect(const csSysMonAlert &alert)
{
}

ssize_t csSysMonSocket::Read(uint8_t *data, ssize_t length, time_t timeout)
{
    struct timeval tv, tv_active;
    uint8_t *ptr = data;
    ssize_t bytes_read, bytes_left = length;

    gettimeofday(&tv_active, NULL);

    while (bytes_left > 0) {
        bytes_read = recv(sd, (char *)ptr, bytes_left, 0);

        if (!bytes_read) throw csSysMonSocketHangupException(sd);
        else if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                gettimeofday(&tv, NULL);
                if (tv.tv_sec - tv_active.tv_sec <= timeout) {
                    usleep(csSocketRetry);
                    continue;
                }
                throw csSysMonSocketTimeoutException(sd);
            }
            throw csSysMonSocketException(errno, "recv", sd);
        }

        ptr += bytes_read;
        bytes_left -= bytes_read;

        gettimeofday(&tv_active, NULL);
    }

    return bytes_read;
}

ssize_t csSysMonSocket::Write(const uint8_t *data, ssize_t length, time_t timeout)
{
    struct timeval tv, tv_active;
    const uint8_t *ptr = data;
    ssize_t bytes_wrote;
    ssize_t bytes_left = length;

    gettimeofday(&tv_active, NULL);

    while (bytes_left > 0) {
        bytes_wrote = send(sd, (const char *)ptr, bytes_left, 0);

        if (!bytes_wrote) throw csSysMonSocketHangupException(sd);
        else if (bytes_wrote < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                gettimeofday(&tv, NULL);
                if (tv.tv_sec - tv_active.tv_sec <= timeout) {
                    usleep(csSocketRetry);
                    continue;
                }
                throw csSysMonSocketTimeoutException(sd);
            }
            throw csSysMonSocketException(errno, "send", sd);
        }

        ptr += bytes_wrote;
        bytes_left -= bytes_wrote;

        gettimeofday(&tv_active, NULL);
    }

    return bytes_wrote;
}

csSysMonSocketClient::csSysMonSocketClient(const string &socket_path)
    : csSysMonSocket(socket_path) { }

csSysMonSocketClient::csSysMonSocketClient(int sd, const string &socket_path)
    : csSysMonSocket(sd, socket_path) { }

void csSysMonSocketClient::Connect(int timeout)
{
    int rc, attempts = 0;
    do {
        rc = connect(sd, (const struct sockaddr *)&sa, sizeof(struct sockaddr_un));
        if (rc == 0) break;
        sleep(1);
    }
    while ((errno == EAGAIN || errno == EWOULDBLOCK) && ++attempts != timeout);

    if (rc != 0) throw csSysMonSocketException(errno, "Socket connect");

    csLog::Log(csLog::Debug, "SysMon client connected to: %s",
        socket_path.c_str());
}

csSysMonSocketServer::csSysMonSocketServer(const string &socket_path)
    : csSysMonSocket(socket_path)
{
    unlink(socket_path.c_str());

    if (bind(sd, (struct sockaddr *)&sa, sizeof(struct sockaddr_un)) != 0)
        throw csSysMonSocketException(errno, "Binding socket");
    if (listen(sd, SOMAXCONN) != 0)
        throw csSysMonSocketException(errno, "Listening on socket");
}

csSysMonSocketClient *csSysMonSocketServer::Accept(void)
{
    int client_sd;
    struct sockaddr_un sa_client;
    socklen_t sa_len = sizeof(struct sockaddr_un);
    if ((client_sd = accept(sd, (struct sockaddr *)&sa_client, &sa_len)) < 0)
        throw csSysMonSocketException(errno, "Accepting client connection");

    csLog::Log(csLog::Debug, "SysMon client connection accepted: %d", client_sd);

    return new csSysMonSocketClient(client_sd, socket_path);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
