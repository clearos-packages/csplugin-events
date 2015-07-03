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

#include <sstream>

#include <unistd.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>

#include <openssl/sha.h>

#include "events-alert.h"
#include "events-conf.h"
#include "events-db.h"

csEventsDb::csEventsDb(csDbType type)
    : type(type)
{
}

static void *csEventsDb_sqlite_log(void *param, int i, const char *s)
{
    return NULL;
}

static int csEventsDb_sqlite_exec(void *param, int argc, char **argv, char **colname)
{
    for (int i = 0; i < argc; i++) {
        csLog::Log(csLog::Debug, "%s = %s", colname[i], argv[i] ? argv[i] : "(null)");
    }
    return 0;
}

static int csEventsDb_sqlite_select_alert(
    void *param, int argc, char **argv, char **colname)
{
    if (argc == 0) return 0;

    unsigned long long v;
    csEventsAlert *alert = new csEventsAlert();

    for (int i = 0; i < argc; i++) {
        csLog::Log(csLog::Debug, "%s = %s", colname[i], argv[i] ? argv[i] : "(null)");

        if (!strcasecmp(colname[i], "id")) {
            v = strtoull(argv[i], NULL, 0);
            alert->SetId((int64_t)v);
        }
        else if (!strcasecmp(colname[i], "created")) {
            v = strtoull(argv[i], NULL, 0);
            alert->SetCreated((time_t)v);
        }
        else if (!strcasecmp(colname[i], "updated")) {
            v = strtoull(argv[i], NULL, 0);
            alert->SetUpdated((time_t)v);
        }
        else if (!strcasecmp(colname[i], "flags")) {
            v = strtoull(argv[i], NULL, 0);
            alert->SetFlags((uint32_t)v);
        }
        else if (!strcasecmp(colname[i], "type")) {
            v = strtoull(argv[i], NULL, 0);
            alert->SetType((uint32_t)v);
        }
        else if (!strcasecmp(colname[i], "user")) {
            alert->SetUser(argv[i]);
        }
        else if (!strcasecmp(colname[i], "origin")) {
            alert->SetOrigin(argv[i]);
        }
        else if (!strcasecmp(colname[i], "basename")) {
            alert->SetBasename(argv[i]);
        }
        else if (!strcasecmp(colname[i], "uuid")) {
            alert->SetUUID(argv[i]);
        }
        else if (!strcasecmp(colname[i], "desc")) {
            alert->SetDescription(argv[i]);
        }
    }

    vector<csEventsAlert *> *result = reinterpret_cast<vector<csEventsAlert *> *>(param);
    result->push_back(alert);

    return 0;
}

static int csEventsDb_sqlite_select_types(
    void *param, int argc, char **argv, char **colname)
{
    if (argc == 0) return 0;

    unsigned long long id = 0ull;
    string tag;
    csAlertIdMap *result = reinterpret_cast<csAlertIdMap *>(param);

    for (int i = 0; i < argc; i++) {
        csLog::Log(csLog::Debug, "%s = %s", colname[i], argv[i] ? argv[i] : "(null)");

        if (!strcasecmp(colname[i], "id")) {
            id = strtoull(argv[i], NULL, 0);
        }
        else if (!strcasecmp(colname[i], "tag")) {
            tag = argv[i];
        }
    }

    if (id > 0ull) (*result)[id] = tag;

    return 0;
}

static int csEventsDb_sqlite_select_overrides(
    void *param, int argc, char **argv, char **colname)
{
    if (argc == 0) return 0;

    uint32_t type = 0, level = csEventsAlert::csAF_NULL;
    map<uint32_t, uint32_t> *result = reinterpret_cast<map<uint32_t, uint32_t> *>(param);

    for (int i = 0; i < argc; i++) {
        csLog::Log(csLog::Debug, "%s = %s", colname[i], argv[i] ? argv[i] : "(null)");

        if (!strcasecmp(colname[i], "type"))
            type = (uint32_t)atoi(argv[i]);
        else if (!strcasecmp(colname[i], "level"))
            level = (uint32_t)atoi(argv[i]);
    }

    if (type > 0 && level != csEventsAlert::csAF_NULL) (*result)[type] = level;

    return 0;
}

csEventsDb_sqlite::csEventsDb_sqlite(const string &db_filename)
    : csEventsDb(csDBT_SQLITE), handle(NULL),
    insert_alert(NULL), update_alert(NULL), purge_alerts(NULL),
    insert_stamp(NULL), purge_stamps(NULL),
    last_id(NULL), mark_resolved(NULL), select_by_hash(NULL),
    insert_type(NULL), delete_type(NULL), select_override(NULL),
    insert_override(NULL), update_override(NULL), delete_override(NULL),
    db_filename(db_filename)
{
    csLog::Log(csLog::Debug, "SQLite version: %s", sqlite3_libversion());

    sqlite3_config(SQLITE_CONFIG_LOG, csEventsDb_sqlite_log);
}

void csEventsDb_sqlite::Open(void)
{
    Close();

    int rc;
    if ((rc = sqlite3_open(db_filename.c_str(), &handle)))
        throw csEventsDbException(rc, sqlite3_errstr(rc));

    // Enable foreign keys
    sql.str("");
    sql << _EVENTS_DB_SQLITE_PRAGMA_FOREIGN_KEY;
    Exec(csEventsDb_sqlite_exec);

    // Set ownership and permissions
    uid_t uid = ::csGetUserId(_EVENTS_DB_SQLITE_USER);
    gid_t gid = ::csGetGroupId(_EVENTS_DB_SQLITE_GROUP);
    if ((rc = chown(db_filename.c_str(), uid, gid)) < 0) {
        csLog::Log(csLog::Debug, "%s: chown(%s): %s",
            __PRETTY_FUNCTION__, db_filename.c_str(), strerror(errno));
        throw csEventsDbException(rc, strerror(rc));
    }
    if ((rc = chmod(db_filename.c_str(),
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) < 0) {
        csLog::Log(csLog::Debug, "%s: chmod(%s): %s",
            __PRETTY_FUNCTION__, db_filename.c_str(), strerror(errno));
        throw csEventsDbException(rc, strerror(rc));
    }
}

void csEventsDb_sqlite::Close(void)
{
    if (handle != NULL)
        sqlite3_close(handle);
    if (insert_alert != NULL)
        sqlite3_finalize(insert_alert);
    if (update_alert != NULL)
        sqlite3_finalize(update_alert);
    if (purge_alerts != NULL)
        sqlite3_finalize(purge_alerts);
    if (insert_stamp != NULL)
        sqlite3_finalize(insert_stamp);
    if (purge_stamps != NULL)
        sqlite3_finalize(purge_stamps);
    if (last_id != NULL)
        sqlite3_finalize(last_id);
    if (mark_resolved != NULL)
        sqlite3_finalize(mark_resolved);
    if (select_by_hash != NULL)
        sqlite3_finalize(select_by_hash);
    if (insert_type != NULL)
        sqlite3_finalize(insert_type);
    if (delete_type != NULL)
        sqlite3_finalize(delete_type);
    if (select_override != NULL)
        sqlite3_finalize(select_override);
    if (insert_override != NULL)
        sqlite3_finalize(insert_override);
    if (update_override != NULL)
        sqlite3_finalize(update_override);
    if (delete_override != NULL)
        sqlite3_finalize(delete_override);
}

void csEventsDb_sqlite::Create(void)
{
    int rc;

    // Create alerts
    sql.str("");
    sql << _EVENTS_DB_SQLITE_CREATE_ALERTS;
    Exec(csEventsDb_sqlite_exec);
    // Create stamps
    sql.str("");
    sql << _EVENTS_DB_SQLITE_CREATE_STAMPS;
    Exec(csEventsDb_sqlite_exec);
    // Create groups
    sql.str("");
    sql << _EVENTS_DB_SQLITE_CREATE_GROUPS;
    Exec(csEventsDb_sqlite_exec);
    // Create types
    sql.str("");
    sql << _EVENTS_DB_SQLITE_CREATE_TYPES;
    Exec(csEventsDb_sqlite_exec);
    // Create level overrides
    sql.str("");
    sql << _EVENTS_DB_SQLITE_CREATE_OVERRIDES;
    Exec(csEventsDb_sqlite_exec);

    // Prepare statements
    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_SELECT_LAST_ID,
        strlen(_EVENTS_DB_SQLITE_SELECT_LAST_ID) + 1,
        &last_id, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "last_id", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_SELECT_ALERT_BY_HASH,
        strlen(_EVENTS_DB_SQLITE_SELECT_ALERT_BY_HASH) + 1,
        &select_by_hash, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "select_by_hash", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_INSERT_ALERT,
        strlen(_EVENTS_DB_SQLITE_INSERT_ALERT) + 1,
        &insert_alert, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "insert_alert", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_UPDATE_ALERT,
        strlen(_EVENTS_DB_SQLITE_UPDATE_ALERT) + 1,
        &update_alert, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "update_alert", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_PURGE_ALERTS,
        strlen(_EVENTS_DB_SQLITE_PURGE_ALERTS) + 1,
        &purge_alerts, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "purge_alerts", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_INSERT_STAMP,
        strlen(_EVENTS_DB_SQLITE_INSERT_STAMP) + 1,
        &insert_stamp, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "insert_stamp", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_PURGE_STAMPS,
        strlen(_EVENTS_DB_SQLITE_PURGE_STAMPS) + 1,
        &purge_stamps, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "purge_stamps", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_MARK_RESOLVED,
        strlen(_EVENTS_DB_SQLITE_MARK_RESOLVED) + 1,
        &mark_resolved, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "mark_resolved", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_INSERT_TYPE,
        strlen(_EVENTS_DB_SQLITE_INSERT_TYPE) + 1,
        &insert_type, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "insert_type", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_DELETE_TYPE,
        strlen(_EVENTS_DB_SQLITE_DELETE_TYPE) + 1,
        &delete_type, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "delete_type", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_SELECT_OVERRIDE,
        strlen(_EVENTS_DB_SQLITE_SELECT_OVERRIDE) + 1,
        &select_override, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "select_override", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_INSERT_OVERRIDE,
        strlen(_EVENTS_DB_SQLITE_INSERT_OVERRIDE) + 1,
        &insert_override, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "insert_override", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_UPDATE_OVERRIDE,
        strlen(_EVENTS_DB_SQLITE_UPDATE_OVERRIDE) + 1,
        &update_override, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "update_override", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(handle,
        _EVENTS_DB_SQLITE_DELETE_OVERRIDE,
        strlen(_EVENTS_DB_SQLITE_DELETE_OVERRIDE) + 1,
        &delete_override, NULL);
    if (rc != SQLITE_OK) {
        csLog::Log(csLog::Debug, "%s: sqlite3_prepare(%s): %s",
            __PRETTY_FUNCTION__, "delete_override", sqlite3_errstr(rc));
        throw csEventsDbException(rc, sqlite3_errstr(rc));
    }
}

void csEventsDb_sqlite::Drop(void)
{
    vector<string> tables;
    tables.push_back("alerts");
    tables.push_back("stamps");
    tables.push_back("groups");
    tables.push_back("types");
    tables.push_back("overrides");

    for (vector<string>::iterator i = tables.begin(); i != tables.end(); i++) {
        sql.str("");
        sql << "DROP TABLE IF EXISTS " << (*i) << ';';
        Exec(csEventsDb_sqlite_exec);
    }
}

int64_t csEventsDb_sqlite::GetLastId(const string &table)
{
    int64_t id = 0;
    int rc, index = 0;

    try {
        // Table name
        index = sqlite3_bind_parameter_index(last_id, "@table_name");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: table_name");
        if ((rc = sqlite3_bind_text(last_id, index,
            table.c_str(), table.length(), SQLITE_TRANSIENT)) != SQLITE_OK)
            throw csEventsDbException(rc, sqlite3_errstr(rc));

        do {
            rc = sqlite3_step(last_id);
            if (rc == SQLITE_BUSY) { usleep(5000); continue; }
            if (rc == SQLITE_ROW) {
                id = static_cast<int64_t>(sqlite3_column_int64(last_id, 0));
                break;
            }
        }
        while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

        if (rc == SQLITE_ERROR) {
            rc = sqlite3_errcode(handle);
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        csLog::Log(csLog::Debug, "%s:%d: %p: %d",
            __PRETTY_FUNCTION__, __LINE__, handle, id);

        sqlite3_reset(last_id);
    }
    catch (csException &e) {
        sqlite3_reset(last_id);
        throw;
    }

    return id;
}

uint32_t csEventsDb_sqlite::SelectAlert(const string &where, vector<csEventsAlert *> *result)
{
    sql.str("");
    sql << _EVENTS_DB_SQLITE_SELECT_ALERT << " " << where << ";";

    Exec(csEventsDb_sqlite_select_alert, (void *)result);

    return (uint32_t)result->size();
}

void csEventsDb_sqlite::InsertAlert(csEventsAlert &alert)
{
    int rc, index = 0;
    int64_t hash_id = -1;

    alert.UpdateHash();

    try {
        // Hash
        index = sqlite3_bind_parameter_index(select_by_hash, "@hash");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: hash");
        if ((rc = sqlite3_bind_text(select_by_hash, index,
            alert.GetHashChar(), alert.GetHashLength(), SQLITE_TRANSIENT)) != SQLITE_OK) {
            csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                __PRETTY_FUNCTION__, "select_by_hash", "hash", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        do {
            rc = sqlite3_step(select_by_hash);
            if (rc == SQLITE_BUSY) { usleep(5000); continue; }
            if (rc == SQLITE_ROW) {
                hash_id = static_cast<int64_t>(sqlite3_column_int64(select_by_hash, 0));
                break;
            }
        }
        while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

        if (rc == SQLITE_ERROR) {
            rc = sqlite3_errcode(handle);
            csLog::Log(csLog::Debug, "%s: sqlite3_step(%s): %s",
                __PRETTY_FUNCTION__, "select_by_hash", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        sqlite3_reset(select_by_hash);
    }
    catch (csException &e) {
        sqlite3_reset(select_by_hash);
        throw;
    }

    if (hash_id < 0) {
        try {
            // Created
            index = sqlite3_bind_parameter_index(insert_alert, "@created");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: created");
            if ((rc = sqlite3_bind_int64(insert_alert,
                index, static_cast<sqlite3_int64>(alert.GetCreated()))) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "insert_alert", "hash", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }
            // Updated
            time_t updated = alert.GetCreated();
            index = sqlite3_bind_parameter_index(insert_alert, "@updated");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: updated");
            if ((rc = sqlite3_bind_int64(insert_alert,
                index, static_cast<sqlite3_int64>(updated))) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "insert_alert", "updated", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }
            // Hash
            index = sqlite3_bind_parameter_index(insert_alert, "@hash");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: hash");
            if ((rc = sqlite3_bind_text(insert_alert, index,
                alert.GetHashChar(), alert.GetHashLength(), SQLITE_TRANSIENT)) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "insert_alert", "hash", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }
            // Flags
            index = sqlite3_bind_parameter_index(insert_alert, "@flags");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: flags");
            if ((rc = sqlite3_bind_int64(insert_alert,
                index, static_cast<sqlite3_int64>(alert.GetFlags()))) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "insert_alert", "flags", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }
            // Type
            index = sqlite3_bind_parameter_index(insert_alert, "@type");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: type");
            if ((rc = sqlite3_bind_int64(insert_alert,
                index, static_cast<sqlite3_int64>(alert.GetType()))) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "insert_alert", "type", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }
            // User
            index = sqlite3_bind_parameter_index(insert_alert, "@user");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: user");
            if ((rc = sqlite3_bind_int64(insert_alert,
                index, static_cast<sqlite3_int64>(alert.GetUser()))) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "insert_alert", "user", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }
            // Origin
            index = sqlite3_bind_parameter_index(insert_alert, "@origin");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: origin");
            if ((rc = sqlite3_bind_text(insert_alert, index,
                alert.GetOriginChar(), alert.GetOriginLength(), SQLITE_TRANSIENT)) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "insert_alert", "origin", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }
            // Basename
            index = sqlite3_bind_parameter_index(insert_alert, "@basename");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: basename");
            if ((rc = sqlite3_bind_text(insert_alert, index,
                alert.GetBasenameChar(), alert.GetBasenameLength(), SQLITE_TRANSIENT)) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "insert_alert", "basename", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }
            // UUID
            index = sqlite3_bind_parameter_index(insert_alert, "@uuid");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: uuid");
            if ((rc = sqlite3_bind_text(insert_alert, index,
                alert.GetUUIDChar(), alert.GetUUIDLength(), SQLITE_TRANSIENT)) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "insert_alert", "uuid", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }
            // Description
            index = sqlite3_bind_parameter_index(insert_alert, "@desc");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: desc");
            if ((rc = sqlite3_bind_text(insert_alert, index,
                alert.GetDescriptionChar(), alert.GetDescriptionLength(),
                SQLITE_TRANSIENT)) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "insert_alert", "desc", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }

            do {
                rc = sqlite3_step(insert_alert);
                if (rc == SQLITE_BUSY) { usleep(5000); continue; }
            }
            while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

            if (rc == SQLITE_ERROR) {
                rc = sqlite3_errcode(handle);
                csLog::Log(csLog::Debug, "%s: sqlite3_step(%s): %s",
                    __PRETTY_FUNCTION__, "insert_alert", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }

            alert.SetId(GetLastId("alerts"));

            sqlite3_reset(insert_alert);
        }
        catch (csException &e) {
            sqlite3_reset(insert_alert);
            throw;
        }
    }
    else {
        try {
            // ID
            index = sqlite3_bind_parameter_index(update_alert, "@id");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: id");
            if ((rc = sqlite3_bind_int64(update_alert,
                index, static_cast<sqlite3_int64>(hash_id))) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "update_alert", "id", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }
            // Stamp
            index = sqlite3_bind_parameter_index(update_alert, "@stamp");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: stamp");
            if ((rc = sqlite3_bind_int64(update_alert,
                index, static_cast<sqlite3_int64>(time(NULL)))) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "update_alert", "stamp", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }
            // Flags
            index = sqlite3_bind_parameter_index(update_alert, "@flags");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: flags");
            if ((rc = sqlite3_bind_int64(update_alert,
                index, static_cast<sqlite3_int64>(alert.GetFlags()))) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "update_alert", "flags", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }
            // Description
            index = sqlite3_bind_parameter_index(update_alert, "@desc");
            if (index == 0) throw csException(EINVAL, "SQL parameter missing: desc");
            if ((rc = sqlite3_bind_text(update_alert, index,
                alert.GetDescriptionChar(), alert.GetDescriptionLength(),
                SQLITE_TRANSIENT)) != SQLITE_OK) {
                csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                    __PRETTY_FUNCTION__, "update_alert", "desc", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }

            do {
                rc = sqlite3_step(update_alert);
                if (rc == SQLITE_BUSY) { usleep(5000); continue; }
            }
            while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

            if (rc == SQLITE_ERROR) {
                rc = sqlite3_errcode(handle);
                csLog::Log(csLog::Debug, "%s: sqlite3_step(%s): %s",
                    __PRETTY_FUNCTION__, "update_alert", sqlite3_errstr(rc));
                throw csEventsDbException(rc, sqlite3_errstr(rc));
            }

            alert.SetId(hash_id);

            sqlite3_reset(update_alert);
        }
        catch (csException &e) {
            sqlite3_reset(update_alert);
            throw;
        }
    }

    try {
        // ID
        index = sqlite3_bind_parameter_index(insert_stamp, "@aid");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: aid");
        if ((rc = sqlite3_bind_int64(insert_stamp,
            index, static_cast<sqlite3_int64>(alert.GetId()))) != SQLITE_OK) {
            csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                __PRETTY_FUNCTION__, "insert_stamp", "aid", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }
        // Stamp
        index = sqlite3_bind_parameter_index(insert_stamp, "@stamp");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: stamp");
        if ((rc = sqlite3_bind_int64(insert_stamp,
            index, static_cast<sqlite3_int64>(alert.GetUpdated()))) != SQLITE_OK) {
            csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                __PRETTY_FUNCTION__, "insert_stamp", "stamp", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        do {
            rc = sqlite3_step(insert_stamp);
            if (rc == SQLITE_BUSY) { usleep(5000); continue; }
        }
        while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

        if (rc == SQLITE_ERROR) {
            rc = sqlite3_errcode(handle);
            csLog::Log(csLog::Debug, "%s: sqlite3_step(%s): %s",
                __PRETTY_FUNCTION__, "insert_stamp", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        sqlite3_reset(insert_stamp);
    }
    catch (csException &e) {
        sqlite3_reset(insert_stamp);
        throw;
    }
}

void csEventsDb_sqlite::PurgeAlerts(const csEventsAlert &alert, time_t age)
{
    int rc, index = 0;

    try {
        // Max age (alerts)
        index = sqlite3_bind_parameter_index(purge_alerts, "@max_age");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: max_age");
        if ((rc = sqlite3_bind_int64(purge_alerts,
            index, static_cast<sqlite3_int64>(age))) != SQLITE_OK)
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        // csAF_FLG_RESOLVED (alerts)
        index = sqlite3_bind_parameter_index(purge_alerts, "@csAF_FLG_RESOLVED");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: csAF_FLG_RESOLVED");
        if ((rc = sqlite3_bind_int64(purge_alerts, index,
            static_cast<sqlite3_int64>(csEventsAlert::csAF_FLG_RESOLVED))) != SQLITE_OK)
            throw csEventsDbException(rc, sqlite3_errstr(rc));
/*
        // Max age (stamps)
        index = sqlite3_bind_parameter_index(purge_stamps, "@max_age");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: max_age");
        if ((rc = sqlite3_bind_int64(purge_stamps,
            index, static_cast<sqlite3_int64>(age))) != SQLITE_OK)
            throw csEventsDbException(rc, sqlite3_errstr(rc));
*/
        // Run purge alerts
        do {
            rc = sqlite3_step(purge_alerts);
            if (rc == SQLITE_BUSY) { usleep(5000); continue; }
        }
        while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

        if (rc == SQLITE_ERROR) {
            rc = sqlite3_errcode(handle);
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }
/*
        // Run purge stamps
        do {
            rc = sqlite3_step(purge_stamps);
            if (rc == SQLITE_BUSY) { usleep(5000); continue; }
        }
        while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

        if (rc == SQLITE_ERROR) {
            rc = sqlite3_errcode(handle);
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }
*/
        sqlite3_reset(purge_alerts);
//        sqlite3_reset(purge_stamps);
    }
    catch (csException &e) {
        sqlite3_reset(purge_alerts);
        sqlite3_reset(purge_stamps);
        throw;
    }
}

void csEventsDb_sqlite::MarkAsResolved(uint32_t type)
{
    int rc, index = 0;

    try {
        // csAF_FLG_RESOLVED
        index = sqlite3_bind_parameter_index(mark_resolved, "@csAF_FLG_RESOLVED");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: csAF_FLG_RESOLVED");
        if ((rc = sqlite3_bind_int64(mark_resolved, index,
            static_cast<sqlite3_int64>(csEventsAlert::csAF_FLG_RESOLVED))) != SQLITE_OK)
            throw csEventsDbException(rc, sqlite3_errstr(rc));

        // Type
        index = sqlite3_bind_parameter_index(mark_resolved, "@type");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: type");
        if ((rc = sqlite3_bind_int64(mark_resolved,
            index, static_cast<sqlite3_int64>(type))) != SQLITE_OK)
            throw csEventsDbException(rc, sqlite3_errstr(rc));

        do {
            rc = sqlite3_step(mark_resolved);
            if (rc == SQLITE_BUSY) { usleep(5000); continue; }
        }
        while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

        if (rc == SQLITE_ERROR) {
            rc = sqlite3_errcode(handle);
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        sqlite3_reset(mark_resolved);
    }
    catch (csException &e) {
        sqlite3_reset(mark_resolved);
        throw;
    }
}

void csEventsDb_sqlite::InsertType(const string &tag, const string &basename)
{
    int rc, index = 0;

    try {
        // Tag
        index = sqlite3_bind_parameter_index(insert_type, "@tag");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: tag");
        if ((rc = sqlite3_bind_text(insert_type, index,
            tag.c_str(), tag.length(), SQLITE_TRANSIENT)) != SQLITE_OK)
            throw csEventsDbException(rc, sqlite3_errstr(rc));

        // Basename
        index = sqlite3_bind_parameter_index(insert_type, "@basename");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: basename");
        if ((rc = sqlite3_bind_text(insert_type, index,
            basename.c_str(), basename.length(), SQLITE_TRANSIENT)) != SQLITE_OK)
            throw csEventsDbException(rc, sqlite3_errstr(rc));

        // Run insert type
        do {
            rc = sqlite3_step(insert_type);
            if (rc == SQLITE_BUSY) { usleep(5000); continue; }
        }
        while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

        if (rc == SQLITE_ERROR) {
            rc = sqlite3_errcode(handle);
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        sqlite3_reset(insert_type);
    }
    catch (csException &e) {
        sqlite3_reset(insert_type);
        throw;
    }
}

void csEventsDb_sqlite::DeleteType(const string &tag)
{
    int rc, index = 0;

    try {
        // Tag
        index = sqlite3_bind_parameter_index(delete_type, "@tag");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: tag");
        if ((rc = sqlite3_bind_text(delete_type, index,
            tag.c_str(), tag.length(), SQLITE_TRANSIENT)) != SQLITE_OK)
            throw csEventsDbException(rc, sqlite3_errstr(rc));

        // Run delete type
        do {
            rc = sqlite3_step(delete_type);
            if (rc == SQLITE_BUSY) { usleep(5000); continue; }
        }
        while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

        if (rc == SQLITE_ERROR) {
            rc = sqlite3_errcode(handle);
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        sqlite3_reset(delete_type);
    }
    catch (csException &e) {
        sqlite3_reset(delete_type);
        throw;
    }
}

uint32_t csEventsDb_sqlite::SelectTypes(csAlertIdMap *result)
{
    sql.str("");
    sql << _EVENTS_DB_SQLITE_SELECT_TYPES;

    Exec(csEventsDb_sqlite_select_types, (void *)result);

    return (uint32_t)result->size();
}

uint32_t csEventsDb_sqlite::SelectOverride(uint32_t type)
{
    int rc, index;
    uint32_t level = csEventsAlert::csAF_NULL;

    try {
        // Type
        index = sqlite3_bind_parameter_index(select_override, "@type");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: type");
        if ((rc = sqlite3_bind_int64(select_override, index,
            static_cast<sqlite3_int64>(type))) != SQLITE_OK) {
            csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                __PRETTY_FUNCTION__, "select_override", "type", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        do {
            rc = sqlite3_step(select_override);
            if (rc == SQLITE_BUSY) { usleep(5000); continue; }
            if (rc == SQLITE_ROW) {
                level = static_cast<uint32_t>(sqlite3_column_int64(select_override, 0));
                break;
            }
        }
        while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

        if (rc == SQLITE_ERROR) {
            rc = sqlite3_errcode(handle);
            csLog::Log(csLog::Debug, "%s: sqlite3_step(%s): %s",
                __PRETTY_FUNCTION__, "select_override", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        sqlite3_reset(select_override);
    }
    catch (csException &e) {
        sqlite3_reset(select_override);
        throw;
    }

    return level;
}

uint32_t csEventsDb_sqlite::SelectOverrides(map<uint32_t, uint32_t> *result)
{
    sql.str("");
    sql << _EVENTS_DB_SQLITE_SELECT_OVERRIDES;

    Exec(csEventsDb_sqlite_select_overrides, (void *)result);

    return (uint32_t)result->size();
}

void csEventsDb_sqlite::InsertOverride(uint32_t type, uint32_t level)
{
    int rc, index;

    try {
        // Type
        index = sqlite3_bind_parameter_index(insert_override, "@type");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: type");
        if ((rc = sqlite3_bind_int64(insert_override,
            index, static_cast<sqlite3_int64>(type))) != SQLITE_OK) {
            csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                __PRETTY_FUNCTION__, "insert_override", "type", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }
        // Level
        index = sqlite3_bind_parameter_index(insert_override, "@level");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: level");
        if ((rc = sqlite3_bind_int64(insert_override,
            index, static_cast<sqlite3_int64>(level))) != SQLITE_OK) {
            csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                __PRETTY_FUNCTION__, "insert_override", "flags", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        do {
            rc = sqlite3_step(insert_override);
            if (rc == SQLITE_BUSY) { usleep(5000); continue; }
        }
        while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

        if (rc == SQLITE_ERROR) {
            rc = sqlite3_errcode(handle);
            csLog::Log(csLog::Debug, "%s: sqlite3_step(%s): %s",
                __PRETTY_FUNCTION__, "insert_override", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        sqlite3_reset(insert_override);
    }
    catch (csException &e) {
        sqlite3_reset(insert_override);
        throw;
    }
}

void csEventsDb_sqlite::UpdateOverride(uint32_t type, uint32_t level)
{
    int rc, index;

    try {
        // Type
        index = sqlite3_bind_parameter_index(update_override, "@type");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: type");
        if ((rc = sqlite3_bind_int64(update_override,
            index, static_cast<sqlite3_int64>(type))) != SQLITE_OK) {
            csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                __PRETTY_FUNCTION__, "update_override", "type", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }
        // Level
        index = sqlite3_bind_parameter_index(update_override, "@level");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: level");
        if ((rc = sqlite3_bind_int64(update_override,
            index, static_cast<sqlite3_int64>(level))) != SQLITE_OK) {
            csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                __PRETTY_FUNCTION__, "update_override", "level", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        do {
            rc = sqlite3_step(update_override);
            if (rc == SQLITE_BUSY) { usleep(5000); continue; }
        }
        while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

        if (rc == SQLITE_ERROR) {
            rc = sqlite3_errcode(handle);
            csLog::Log(csLog::Debug, "%s: sqlite3_step(%s): %s",
                __PRETTY_FUNCTION__, "update_override", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        sqlite3_reset(update_override);
    }
    catch (csException &e) {
        sqlite3_reset(update_override);
        throw;
    }
}

void csEventsDb_sqlite::DeleteOverride(uint32_t type)
{
    int rc, index = 0;

    try {
        // Type
        index = sqlite3_bind_parameter_index(delete_override, "@type");
        if (index == 0) throw csException(EINVAL, "SQL parameter missing: type");
        if ((rc = sqlite3_bind_int64(delete_override,
            index, static_cast<sqlite3_int64>(type))) != SQLITE_OK) {
            csLog::Log(csLog::Debug, "%s: sqlite3_bind(%s, %s): %s",
                __PRETTY_FUNCTION__, "delete_override", "type", sqlite3_errstr(rc));
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        // Run delete type
        do {
            rc = sqlite3_step(delete_override);
            if (rc == SQLITE_BUSY) { usleep(5000); continue; }
        }
        while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

        if (rc == SQLITE_ERROR) {
            rc = sqlite3_errcode(handle);
            throw csEventsDbException(rc, sqlite3_errstr(rc));
        }

        sqlite3_reset(delete_override);
    }
    catch (csException &e) {
        sqlite3_reset(delete_override);
        throw;
    }
}

void csEventsDb_sqlite::Exec(int (*callback)(void *, int, char**, char **), void *param)
{
    int rc;

    csLog::Log(csLog::Debug, "%s:%d: %p: %s",
        __PRETTY_FUNCTION__, __LINE__, handle, sql.str().c_str());

    char *es = NULL;
    do {
        rc = sqlite3_exec(handle, sql.str().c_str(), callback, param, &es);
        if (rc == SQLITE_BUSY) usleep(5000);
        else break;
    }
    while (rc != SQLITE_OK);

    if (rc != SQLITE_OK) {
        errstr.str("");
        errstr << es;
        sqlite3_free(es);
        throw csEventsDbException(rc, errstr.str().c_str());
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
