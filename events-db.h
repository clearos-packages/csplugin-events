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

#ifndef _EVENTS_DB_H
#define _EVENTS_DB_H

#include "events-db-sql.h"

#define _EVENTS_DB_SQLITE_USER      "clearsync"
#define _EVENTS_DB_SQLITE_GROUP     "webconfig"

class csEventsDbException : public csException
{
public:
    explicit csEventsDbException(int e, const char *s)
        : csException(e, s) { }
};

class csEventsDb
{
public:
    enum csDbType {
        csDBT_NULL,
        csDBT_SQLITE,
    };

    csEventsDb(csDbType type = csDBT_NULL);
    virtual ~csEventsDb() { }

    virtual void Open(void) { }
    virtual void Close(void) { }
    virtual void Create(void) { }
    virtual void Drop(void) { }
    virtual int64_t GetLastId(const string &table) { return 0; }

    virtual uint32_t SelectAlert(const string &where, vector<csEventsAlert *> *result) { return 0; }
    virtual void InsertAlert(csEventsAlert &alert) { }
    virtual void UpdateAlert(const csEventsAlert &alert) { }
    virtual void PurgeAlerts(const csEventsAlert &alert, time_t age) { }

    virtual void MarkAsResolved(uint32_t type) { };

    virtual void InsertType(const string &tag, const string &basename) { }
    virtual void DeleteType(const string &tag) { }
    virtual uint32_t SelectTypes(map<uint32_t, string> *result) { return 0; }

    virtual uint32_t SelectOverride(uint32_t type) { return 0; }
    virtual uint32_t SelectOverrides(map<uint32_t, uint32_t> *result) { return 0; }
    virtual void InsertOverride(uint32_t type, uint32_t level) { }
    virtual void UpdateOverride(uint32_t type, uint32_t level) { }
    virtual void DeleteOverride(uint32_t type) { }

protected:
    csDbType type;
};

typedef map<string, string> csEventsDb_sqlite_result;

class csEventsDb_sqlite : public csEventsDb
{
public:
    csEventsDb_sqlite(const string &db_filename);
    virtual ~csEventsDb_sqlite() { Close(); };

    void Open(void);
    void Close(void);
    void Create(void);
    void Drop(void);
    virtual int64_t GetLastId(const string &table);

    uint32_t SelectAlert(const string &where, vector<csEventsAlert *> *result);
    void InsertAlert(csEventsAlert &alert);
    void PurgeAlerts(const csEventsAlert &alert, time_t age);

    void MarkAsResolved(uint32_t type);

    void InsertType(const string &tag, const string &basename);
    void DeleteType(const string &tag);
    uint32_t SelectTypes(map<uint32_t, string> *result);

    uint32_t SelectOverride(uint32_t type);
    uint32_t SelectOverrides(map<uint32_t, uint32_t> *result);
    void InsertOverride(uint32_t type, uint32_t level);
    void UpdateOverride(uint32_t type, uint32_t level);
    void DeleteOverride(uint32_t type);

protected:
    void Exec(int (*callback)(void *, int, char **, char **), void *param = NULL);

    sqlite3 *handle;
    sqlite3_stmt *insert_alert;
    sqlite3_stmt *update_alert;
    sqlite3_stmt *purge_alerts;
    sqlite3_stmt *insert_stamp;
    sqlite3_stmt *purge_stamps;
    sqlite3_stmt *last_id;
    sqlite3_stmt *mark_resolved;
    sqlite3_stmt *select_by_hash;
    sqlite3_stmt *insert_type;
    sqlite3_stmt *delete_type;
    sqlite3_stmt *select_override;
    sqlite3_stmt *insert_override;
    sqlite3_stmt *update_override;
    sqlite3_stmt *delete_override;

    string db_filename;
    ostringstream sql;
    ostringstream errstr;
    csEventsDb_sqlite_result result;
};

#endif // _EVENTS_DB_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
