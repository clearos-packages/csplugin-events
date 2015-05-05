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

#ifndef _EVENTS_SOCKET
#define _EVENTS_SOCKET

#define _EVENTS_SOCKET_PROTOVER         0x20141112
#define _EVENTS_SOCKET_TIMEOUT_RW       10
#define _EVENTS_SOCKET_TIMEOUT_CONNECT  5

enum csEventsOpCode {
    csSMOC_NULL,

    csSMOC_VERSION,
    csSMOC_ALERT_INSERT,
    csSMOC_ALERT_SELECT,
    csSMOC_ALERT_MARK_AS_RESOLVED,
    csSMOC_ALERT_RECORD,

    csSMOC_RESULT = 0xFF,
};

enum csEventsProtoResult {
    csSMPR_OK,
    csSMPR_VERSION_MISMATCH,
    csSMPR_ALERT_MATCHES,
};

class csEventsSocketException : public csException
{
public:
    explicit csEventsSocketException(int e, const char *s)
        : csException(e, s), sd(-1) { }
    explicit csEventsSocketException(int e, const char *s, int sd)
        : csException(e, s), sd(sd) { }

    int GetDescriptor(void) { return sd; }

protected:
    int sd;
};

class csEventsSocketHangupException : public csEventsSocketException
{
public:
    explicit csEventsSocketHangupException(int sd)
        : csEventsSocketException(EINVAL, "Hung-up", sd) { }
};

class csEventsSocketTimeoutException : public csEventsSocketException
{
public:
    explicit csEventsSocketTimeoutException(int sd)
        : csEventsSocketException(EINVAL, "Time-out", sd) { }
};

class csEventsSocketProtocolException : public csEventsSocketException
{
public:
    explicit csEventsSocketProtocolException(int sd, const char *s)
        : csEventsSocketException(EINVAL, s, sd) { }
};

class csEventsSocket
{
public:
    enum csEventsSocketMode {
        csSM_CLIENT,
        csSM_SERVER,
    };

    typedef struct __attribute__ ((__packed__)) {
        uint8_t opcode;
        uint32_t payload_length;
    } csEventsHeader;

    csEventsSocket(const string &socket_path);
    csEventsSocket(int sd, const string &socket_path);
    virtual ~csEventsSocket();

    int GetDescriptor(void) { return sd; }
    uint32_t GetProtoVersion(void) { return proto_version; }
    csEventsOpCode GetOpCode(void) { return (csEventsOpCode)header->opcode; }
    ssize_t GetPayloadLength(void) { return (ssize_t)header->payload_length; }

    void ResetPacket(void)
    {
        payload_index = payload;
        memset((void *)header, 0, sizeof(csEventsHeader));
    }

    csEventsOpCode ReadPacket(void);
    void WritePacket(csEventsOpCode opcode);

    void ReadPacketVar(string &v);
    void ReadPacketVar(csEventsAlert &alert);
    void ReadPacketVar(void *v, size_t length);

    void WritePacketVar(const string &v);
    void WritePacketVar(const csEventsAlert &alert);
    void WritePacketVar(const void *v, size_t length);

    void SetOpCode(csEventsOpCode opc) { header->opcode = (uint8_t)opc; }
    void SetPayload(uint8_t *data, ssize_t length)
    {
        header->payload_length = (uint32_t)length;
    }

    csEventsProtoResult VersionExchange(void);

    void AlertInsert(csEventsAlert &alert);
    uint32_t AlertSelect(const string &where, vector<csEventsAlert *> &result);
    void AlertSelect(csEventsDb *db);
    void AlertMarkAsResolved(csEventsAlert &alert);

    csEventsProtoResult ReadResult(void);
    void WriteResult(csEventsProtoResult result,
        const void *data = NULL, uint32_t length = 0);

protected:
    void Create(void);

    void AllocatePayloadBuffer(ssize_t length);

    ssize_t Read(uint8_t *data, ssize_t length,
        time_t timeout = _EVENTS_SOCKET_TIMEOUT_RW);
    ssize_t Write(const uint8_t *data, ssize_t length,
        time_t timeout = _EVENTS_SOCKET_TIMEOUT_RW);

    int sd;
    struct sockaddr_un sa;
    const string socket_path;
    enum csEventsSocketMode mode;

    long page_size;

    uint8_t *buffer;
    ssize_t buffer_pages;
    ssize_t buffer_length;

    csEventsHeader *header;

    uint8_t *payload;
    uint8_t *payload_index;

    uint32_t proto_version;

    vector<csEventsAlert *> alert_matches;
};

class csEventsSocketClient : public csEventsSocket
{
public:
    csEventsSocketClient(const string &socket_path);
    csEventsSocketClient(int sd, const string &socket_path);
    virtual ~csEventsSocketClient() { }

    void Connect(int timeout = _EVENTS_SOCKET_TIMEOUT_CONNECT);

protected:
};

class csEventsSocketServer : public csEventsSocket
{
public:
    csEventsSocketServer(const string &socket_path);
    virtual ~csEventsSocketServer() { }

    csEventsSocketClient *Accept(void);

protected:
};

#endif // _EVENTS_SOCKET

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
