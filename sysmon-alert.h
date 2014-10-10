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

#ifndef _SYSMON_ALERT_H
#define _SYSMON_ALERT_H

class csSysMonAlert
{
public:
    csSysMonAlert();
    csSysMonAlert(uint32_t id, uint32_t flags, uint32_t type,
        const string &uuid, const string &icon, const string &desc);
    virtual ~csSysMonAlert();

    enum csAlertFlags {
        csAF_NULL           = 0,

        // Priority levels
        ////////////////////////////////////////
        csAF_LVL_NORM       = 0x0000000000000001,
        csAF_LVL_WARN       = 0x0000000000000002,
        csAF_LVL_CRIT       = 0x0000000000000004,

        // Flags
        ////////////////////////////////////////
        // Alert is persistent / exclusive.
        csAF_FLG_PERSIST    = 0x0000000000000100,
        // Alert has been read / viewed.
        csAF_FLG_READ       = 0x0000000000000200,

        csAF_MAX            = 0xffffffffffffffff,
    };

    enum csAlertType {
        csAT_NULL           = 0,
    };

    int64_t GetId(void) const { return id; }
    time_t GetStamp(void) const { return stamp; }
    uint32_t GetFlags(void) const { return flags; }
    uint32_t GetType(void) const { return type; }
    uid_t GetUser(void) const { return user; }
    void GetGroups(vector<gid_t> &groups);
    string GetUUID(void) const { return uuid; };
    const char *GetUUIDChar(void) const { return uuid.c_str(); };
    int GetUUIDLength(void) const { return static_cast<int>(uuid.length()); };
    string GetIcon(void) const { return icon; };
    const char *GetIconChar(void) const { return icon.c_str(); };
    int GetIconLength(void) const { return static_cast<int>(icon.length()); };
    string GetDescription(void) const { return desc; };
    const char *GetDescriptionChar(void) const { return desc.c_str(); };
    int GetDescriptionLength(void) const { return static_cast<int>(desc.length()); };

    void SetId(int64_t id) { this->id = id; };
    void SetStamp(void) { stamp = time(NULL); };
    void SetStamp(time_t stamp) { this->stamp = stamp; };
    void SetFlags(uint32_t flags) { this->flags = flags; };
    void SetFlag(uint32_t flag) { this->flags |= flag; };
    void ClearFlag(uint32_t flag) { this->flags &= ~flag; };
    void SetType(uint32_t type) { this->type = type; };
    void SetUser(uid_t uid) { this->user = uid; };
    void AddGroup(gid_t gid);
    void ClearGroups(void) { groups.clear(); };
    void SetUUID(const string &uuid) { this->uuid = uuid; };
    void SetIcon(const string &icon) { this->icon = icon; };
    void SetDescription(const string &desc) { this->desc = desc; };

protected:
    int64_t id;
    time_t stamp;
    uint32_t flags;
    uint32_t type;
    uid_t user;
    vector<gid_t> groups;
    string uuid;
    string icon;
    string desc;
};

#endif // _SYSMON_ALERT_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
