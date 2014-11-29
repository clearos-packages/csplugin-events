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

#ifndef _SYSMON_SOCKET
#define _SYSMON_SOCKET

#define _SYSMON_SOCKET_PROTOVER         0x20141112
#define _SYSMON_SOCKET_TIMEOUT_RW       10
#define _SYSMON_SOCKET_TIMEOUT_CONNECT  5

enum csSysMonOpCode {
    csSMOC_NULL,

    csSMOC_VERSION,
    csSMOC_ALERT_INSERT,
    csSMOC_ALERT_SELECT,
    csSMOC_ALERT_MARK_AS_READ,
    csSMOC_ALERT_RECORD,

    csSMOC_RESULT = 0xFF,
};

enum csSysMonProtoResult {
    csSMPR_OK,
    csSMPR_VERSION_MISMATCH,
    csSMPR_ALERT_MATCHES,
};

class csSysMonSocketException : public csException
{
public:
    explicit csSysMonSocketException(int e, const char *s)
        : csException(e, s), sd(-1) { }
    explicit csSysMonSocketException(int e, const char *s, int sd)
        : csException(e, s), sd(sd) { }

    int GetDescriptor(void) { return sd; }

protected:
    int sd;
};

class csSysMonSocketHangupException : public csSysMonSocketException
{
public:
    explicit csSysMonSocketHangupException(int sd)
        : csSysMonSocketException(EINVAL, "Hung-up", sd) { }
};

class csSysMonSocketTimeoutException : public csSysMonSocketException
{
public:
    explicit csSysMonSocketTimeoutException(int sd)
        : csSysMonSocketException(EINVAL, "Time-out", sd) { }
};

class csSysMonSocketProtocolException : public csSysMonSocketException
{
public:
    explicit csSysMonSocketProtocolException(int sd, const char *s)
        : csSysMonSocketException(EINVAL, s, sd) { }
};

class csSysMonSocket
{
public:
    enum csSysMonSocketMode {
        csSM_CLIENT,
        csSM_SERVER,
    };

    typedef struct __attribute__ ((__packed__)) {
        uint8_t opcode;
        uint32_t payload_length;
    } csSysMonHeader;

    csSysMonSocket(const string &socket_path);
    csSysMonSocket(int sd, const string &socket_path);
    virtual ~csSysMonSocket();

    int GetDescriptor(void) { return sd; }
    uint32_t GetProtoVersion(void) { return proto_version; }
    csSysMonOpCode GetOpCode(void) { return (csSysMonOpCode)header->opcode; }
    ssize_t GetPayloadLength(void) { return (ssize_t)header->payload_length; }

    void ResetPacket(void)
    {
        payload_index = payload;
        memset((void *)header, 0, sizeof(csSysMonHeader));
    }

    csSysMonOpCode ReadPacket(void);
    void WritePacket(csSysMonOpCode opcode);

    void ReadPacketVar(string &v);
    void ReadPacketVar(csSysMonAlert &alert);
    void ReadPacketVar(void *v, size_t length);

    void WritePacketVar(const string &v);
    void WritePacketVar(const csSysMonAlert &alert);
    void WritePacketVar(const void *v, size_t length);

    void SetOpCode(csSysMonOpCode opc) { header->opcode = (uint8_t)opc; }
    void SetPayload(uint8_t *data, ssize_t length)
    {
        header->payload_length = (uint32_t)length;
    }

    csSysMonProtoResult VersionExchange(void);

    void AlertInsert(csSysMonAlert &alert);
    uint32_t AlertSelect(const string &where, vector<csSysMonAlert *> &result);
    void AlertSelect(csSysMonDb *db);
    void AlertMarkAsRead(csSysMonAlert &alert);

    csSysMonProtoResult ReadResult(void);
    void WriteResult(csSysMonProtoResult result,
        const void *data = NULL, uint32_t length = 0);

protected:
    void Create(void);

    void AllocatePayloadBuffer(ssize_t length);

    ssize_t Read(uint8_t *data, ssize_t length,
        time_t timeout = _SYSMON_SOCKET_TIMEOUT_RW);
    ssize_t Write(const uint8_t *data, ssize_t length,
        time_t timeout = _SYSMON_SOCKET_TIMEOUT_RW);

    int sd;
    struct sockaddr_un sa;
    const string socket_path;
    enum csSysMonSocketMode mode;

    long page_size;

    uint8_t *buffer;
    ssize_t buffer_pages;
    ssize_t buffer_length;

    csSysMonHeader *header;

    uint8_t *payload;
    uint8_t *payload_index;

    uint32_t proto_version;

    vector<csSysMonAlert *> alert_matches;
};

class csSysMonSocketClient : public csSysMonSocket
{
public:
    csSysMonSocketClient(const string &socket_path);
    csSysMonSocketClient(int sd, const string &socket_path);
    virtual ~csSysMonSocketClient() { }

    void Connect(int timeout = _SYSMON_SOCKET_TIMEOUT_CONNECT);

protected:
};

class csSysMonSocketServer : public csSysMonSocket
{
public:
    csSysMonSocketServer(const string &socket_path);
    virtual ~csSysMonSocketServer() { }

    csSysMonSocketClient *Accept(void);

protected:
};

#endif // _SYSMON_SOCKET

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
