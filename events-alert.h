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

#ifndef _EVENTS_ALERT_H
#define _EVENTS_ALERT_H

class csEventsAlert
{
public:
    typedef struct {
        int64_t id;
        time_t created;
        time_t updated;
        uint32_t flags;
        uint32_t type;
        uid_t user;
        vector<gid_t> groups;
        string origin;
        string basename;
        string uuid;
        string desc;
    } csEventsAlertData;

    enum csAlertFlags {
        csAF_NULL           = 0,

        // Priority levels
        ////////////////////////////////////////
        csAF_LVL_NORM       = 0x00000001,
        csAF_LVL_WARN       = 0x00000002,
        csAF_LVL_CRIT       = 0x00000004,

        // Flags
        ////////////////////////////////////////
        // Alert notification has been sent.
        csAF_FLG_NOTIFIED   = 0x00000100,
        // Alert has been read / viewed.
        csAF_FLG_READ       = 0x00000200,

        csAF_MAX            = 0xffffffff,
    };

    enum csAlertType {
        csAT_NULL           = 0,
    };

    csEventsAlert();
    csEventsAlert(uint32_t id, uint32_t flags, uint32_t type, const string &origin,
        const string &basename, const string &uuid, const string &desc);
    virtual ~csEventsAlert();

    void Reset(void);

    const csEventsAlertData *GetDataPtr(void) const
        { return (const csEventsAlertData *)&data; }

    int64_t GetId(void) const { return data.id; }
    time_t GetCreated(void) const { return data.created; }
    time_t GetUpdated(void) const { return data.updated; }
    uint32_t GetFlags(void) const { return data.flags; }
    uint32_t GetType(void) const { return data.type; }
    uid_t GetUser(void) const { return data.user; }
    void GetGroups(vector<gid_t> &groups);
    string GetOrigin(void) const { return data.origin; };
    const char *GetOriginChar(void) const { return data.origin.c_str(); };
    int GetOriginLength(void) const { return static_cast<int>(data.origin.length()); };
    string GetBasename(void) const { return data.basename; };
    const char *GetBasenameChar(void) const { return data.basename.c_str(); };
    int GetBasenameLength(void) const { return static_cast<int>(data.basename.length()); };
    string GetUUID(void) const { return data.uuid; };
    const char *GetUUIDChar(void) const { return data.uuid.c_str(); };
    int GetUUIDLength(void) const { return static_cast<int>(data.uuid.length()); };
    string GetDescription(void) const { return data.desc; };
    const char *GetDescriptionChar(void) const { return data.desc.c_str(); };
    int GetDescriptionLength(void) const { return static_cast<int>(data.desc.length()); };

    void SetData(const csEventsAlertData &data);

    void SetId(int64_t id) { data.id = id; };
    void SetCreated(void) { data.created = time(NULL); };
    void SetCreated(time_t created) { data.created = created; };
    void SetUpdated(void) { data.updated = time(NULL); };
    void SetUpdated(time_t updated) { data.updated = updated; };
    void SetFlags(uint32_t flags) { data.flags = flags; };
    void SetFlag(uint32_t flag) { data.flags |= flag; };
    void ClearFlag(uint32_t flag) { data.flags &= ~flag; };
    void SetType(uint32_t type) { data.type = type; };
    void SetUser(const string &user);
    void SetUser(uid_t uid) { data.user = uid; };
    void AddGroup(gid_t gid);
    void ClearGroups(void) { data.groups.clear(); };
    void SetOrigin(const string &origin) { data.origin = origin; };
    void SetBasename(const string &basename) { data.basename = basename; };
    void SetUUID(const string &uuid) { data.uuid = uuid; };
    void SetDescription(const string &desc) { data.desc = desc; };

    void UpdateHash(void);
    string GetHash(void) { return hash_str; };
    const uint8_t *GetHashBin(void) { return hash; };
    const char *GetHashChar(void) { return hash_str.c_str(); };
    int GetHashLength(void) { return static_cast<int>(hash_str.length()); };

protected:
    csEventsAlertData data;
    uint8_t hash[SHA_DIGEST_LENGTH];
    string hash_str;
};

#endif // _EVENTS_ALERT_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
