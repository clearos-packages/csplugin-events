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

#ifndef _SYSMON_DB_H
#define _SYSMON_DB_H

#define _SYSMON_DB_SQLITE_CREATE_ALERT  "CREATE TABLE IF NOT EXISTS alert(id INTEGER PRIMARY KEY NOT NULL, stamp INTEGER NOT NULL, flags INTEGER NOT NULL, type INTEGER NOT NULL, user INTEGER, uuid TEXT, icon TEXT, desc TEXT NOT NULL);"
#define _SYSMON_DB_SQLITE_CREATE_GROUP  "CREATE TABLE IF NOT EXISTS groups(id INTEGER NOT NULL, gid INTEGER NOT NULL);"
#define _SYSMON_DB_SQLITE_SELECT_MAX_ID "SELECT MAX(id) AS max_id FROM alert;"
#define _SYSMON_DB_SQLITE_INSERT_ALERT  "INSERT INTO alert VALUES(@id, @stamp, @flags, @type, @user, @uuid, @icon, @desc);"
#define _SYSMON_DB_SQLITE_PURGE_ALERTS  "DELETE FROM alert WHERE stamp < @max_age AND flags & @csAF_FLG_READ AND NOT flags & @csAF_FLG_PERSIST;"

class csSysMonDbException : public csException
{
public:
    explicit csSysMonDbException(int e, const char *s)
        : csException(e, s) { }
};

class csSysMonDb
{
public:
    enum csDbType {
        csDBT_NULL,
        csDBT_SQLITE,
    };

    csSysMonDb(csDbType type = csDBT_NULL);
    virtual ~csSysMonDb() { }

    virtual void Open(void) { }
    virtual void Close(void) { }
    virtual void Create(void) { }
    virtual uint32_t GetMaxId(void) { return 0; }

    virtual void SelectAlert(const csSysMonAlert &alert, off_t offset = 0, size_t length = 0) { }
    virtual void InsertAlert(const csSysMonAlert &alert) { }
    virtual void UpdateAlert(const csSysMonAlert &alert) { }
    virtual void PurgeAlerts(const csSysMonAlert &alert, time_t age) { }

protected:
    csDbType type;
};

typedef map<string, string> csSysMonDb_sqlite_result;

class csSysMonDb_sqlite : public csSysMonDb
{
public:
    csSysMonDb_sqlite(const string &db_filename);
    virtual ~csSysMonDb_sqlite() { Close(); };

    void Open(void);
    void Close(void);
    void Create(void);
    virtual uint32_t GetMaxId(void);

    void SelectAlert(const csSysMonAlert &alert, off_t offset = 0, size_t length = 0);
    void InsertAlert(const csSysMonAlert &alert);
    void UpdateAlert(const csSysMonAlert &alert);
    void PurgeAlerts(const csSysMonAlert &alert, time_t age);

protected:
    void Exec(void);

    sqlite3 *handle;
    sqlite3_stmt *insert_alert;
    sqlite3_stmt *purge_alerts;

    string db_filename;
    ostringstream sql;
    ostringstream errstr;
    csSysMonDb_sqlite_result result;
};

#endif // _SYSMON_DB_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
