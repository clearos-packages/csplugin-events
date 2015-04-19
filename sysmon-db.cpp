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

#include <string.h>
#include <sqlite3.h>

#include "sysmon-alert.h"
#include "sysmon-db.h"

csSysMonDb::csSysMonDb(csDbType type)
    : type(type)
{
}

static void *csSysMonDb_sqlite_log(void *param, int i, const char *s)
{
    return NULL;
}

static int csSysMonDb_sqlite_exec(void *param, int argc, char **argv, char **colname)
{
    for (int i = 0; i < argc; i++) {
        csLog::Log(csLog::Debug, "%s = %s", colname[i], argv[i] ? argv[i] : "(null)");
    }
    return 0;
}

static int csSysMonDb_sqlite_select_alert(
    void *param, int argc, char **argv, char **colname)
{
    if (argc == 0) return 0;

    unsigned long long v;
    csSysMonAlert *alert = new csSysMonAlert();

    for (int i = 0; i < argc; i++) {
        csLog::Log(csLog::Debug, "%s = %s", colname[i], argv[i] ? argv[i] : "(null)");

        if (!strcasecmp(colname[i], "id")) {
            v = strtoull(argv[i], NULL, 0);
            alert->SetId((int64_t)v);
        }
        else if (!strcasecmp(colname[i], "stamp")) {
            v = strtoull(argv[i], NULL, 0);
            alert->SetStamp((time_t)v);
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

    vector<csSysMonAlert *> *result = reinterpret_cast<vector<csSysMonAlert *> *>(param);
    result->push_back(alert);

    return 0;
}

csSysMonDb_sqlite::csSysMonDb_sqlite(const string &db_filename)
    : csSysMonDb(csDBT_SQLITE), handle(NULL), insert_alert(NULL),
    purge_alerts(NULL), last_id(NULL), mark_read(NULL), db_filename(db_filename)
{
    csLog::Log(csLog::Debug, "SQLite version: %s", sqlite3_libversion());

    sqlite3_config(SQLITE_CONFIG_LOG, csSysMonDb_sqlite_log);
}

void csSysMonDb_sqlite::Open(void)
{
    Close();

    int rc;
    if ((rc = sqlite3_open(db_filename.c_str(), &handle)))
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
}

void csSysMonDb_sqlite::Close(void)
{
    if (handle != NULL)
        sqlite3_close(handle);
    if (insert_alert != NULL)
        sqlite3_finalize(insert_alert);
    if (purge_alerts != NULL)
        sqlite3_finalize(purge_alerts);
    if (last_id != NULL)
        sqlite3_finalize(last_id);
    if (mark_read != NULL)
        sqlite3_finalize(mark_read);
}

void csSysMonDb_sqlite::Create(void)
{
    sql.str("");
    sql << _SYSMON_DB_SQLITE_CREATE_ALERT;
    Exec(csSysMonDb_sqlite_exec);
    sql.str("");
    sql << _SYSMON_DB_SQLITE_CREATE_GROUP;
    Exec(csSysMonDb_sqlite_exec);
}

void csSysMonDb_sqlite::Drop(void)
{
    sql.str("");
    sql << "DROP TABLE IF EXISTS alerts;";
    Exec(csSysMonDb_sqlite_exec);
    sql.str("");
    sql << "DROP TABLE IF EXISTS groups;";
    Exec(csSysMonDb_sqlite_exec);
}

int64_t csSysMonDb_sqlite::GetLastId(const string &table)
{
    int64_t id = 0;
    int rc, index = 0;

    if (last_id == NULL) {
        rc = sqlite3_prepare_v2(handle,
            _SYSMON_DB_SQLITE_SELECT_LAST_ID,
            strlen(_SYSMON_DB_SQLITE_SELECT_LAST_ID) + 1,
            &last_id, NULL);
        if (rc != SQLITE_OK)
            throw csSysMonDbException(rc, sqlite3_errstr(rc));
    }
    else sqlite3_reset(last_id);

    // Table name
    index = sqlite3_bind_parameter_index(last_id, "@table_name");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: table_name");
    if ((rc = sqlite3_bind_text(last_id, index,
        table.c_str(), table.length(), SQLITE_TRANSIENT)) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));

    do {
        rc = sqlite3_step(last_id);
        csLog::Log(csLog::Debug, "%s:%d: %d", __PRETTY_FUNCTION__, __LINE__, rc);
        if (rc == SQLITE_ROW) {
            id = static_cast<int64_t>(sqlite3_column_int64(last_id, 0));
            break;
        }
    }
    while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

    if (rc == SQLITE_ERROR) {
        rc = sqlite3_errcode(handle);
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    }

    csLog::Log(csLog::Debug, "%s:%d: %p: %d",
        __PRETTY_FUNCTION__, __LINE__, handle, id);

    return id;
}

uint32_t csSysMonDb_sqlite::SelectAlert(const string &where, vector<csSysMonAlert *> *result)
{
    sql.str("");
    sql << _SYSMON_DB_SQLITE_SELECT_ALERT << " " << where << ";";

    Exec(csSysMonDb_sqlite_select_alert, (void *)result);

    return (uint32_t)result->size();
}

void csSysMonDb_sqlite::InsertAlert(const csSysMonAlert &alert)
{
    int rc, index = 0;

    if (insert_alert == NULL) {
        rc = sqlite3_prepare_v2(handle,
            _SYSMON_DB_SQLITE_INSERT_ALERT,
            strlen(_SYSMON_DB_SQLITE_INSERT_ALERT) + 1,
            &insert_alert, NULL);
        if (rc != SQLITE_OK)
            throw csSysMonDbException(rc, sqlite3_errstr(rc));
    }
    else sqlite3_reset(insert_alert);

    // Stamp
    index = sqlite3_bind_parameter_index(insert_alert, "@stamp");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: stamp");
    if ((rc = sqlite3_bind_int64(insert_alert,
        index, static_cast<sqlite3_int64>(alert.GetStamp()))) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    // Flags
    index = sqlite3_bind_parameter_index(insert_alert, "@flags");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: flags");
    if ((rc = sqlite3_bind_int64(insert_alert,
        index, static_cast<sqlite3_int64>(alert.GetFlags()))) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    // Type
    index = sqlite3_bind_parameter_index(insert_alert, "@type");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: type");
    if ((rc = sqlite3_bind_int64(insert_alert,
        index, static_cast<sqlite3_int64>(alert.GetType()))) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    // User
    index = sqlite3_bind_parameter_index(insert_alert, "@user");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: user");
    if ((rc = sqlite3_bind_int64(insert_alert,
        index, static_cast<sqlite3_int64>(alert.GetUser()))) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    // Origin 
    index = sqlite3_bind_parameter_index(insert_alert, "@origin");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: origin");
    if ((rc = sqlite3_bind_text(insert_alert, index,
        alert.GetOriginChar(), alert.GetOriginLength(), SQLITE_TRANSIENT)) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    // Basename
    index = sqlite3_bind_parameter_index(insert_alert, "@basename");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: basename");
    if ((rc = sqlite3_bind_text(insert_alert, index,
        alert.GetBasenameChar(), alert.GetBasenameLength(), SQLITE_TRANSIENT)) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    // UUID
    index = sqlite3_bind_parameter_index(insert_alert, "@uuid");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: uuid");
    if ((rc = sqlite3_bind_text(insert_alert, index,
        alert.GetUUIDChar(), alert.GetUUIDLength(), SQLITE_TRANSIENT)) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    // Description
    index = sqlite3_bind_parameter_index(insert_alert, "@desc");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: desc");
    if ((rc = sqlite3_bind_text(insert_alert, index,
        alert.GetDescriptionChar(), alert.GetDescriptionLength(),
        SQLITE_TRANSIENT)) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));

    do {
        rc = sqlite3_step(insert_alert);
        csLog::Log(csLog::Debug, "%s:%d: %d", __PRETTY_FUNCTION__, __LINE__, rc);
    }
    while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

    if (rc == SQLITE_ERROR) {
        rc = sqlite3_errcode(handle);
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    }

    csLog::Log(csLog::Debug, "%s:%d: %d", __PRETTY_FUNCTION__, __LINE__, alert.GetId());
}

void csSysMonDb_sqlite::UpdateAlert(const csSysMonAlert &alert)
{
    csLog::Log(csLog::Debug, "%s:%d", __PRETTY_FUNCTION__, __LINE__);
}

void csSysMonDb_sqlite::PurgeAlerts(const csSysMonAlert &alert, time_t age)
{
    int rc, index = 0;

    if (purge_alerts == NULL) {
        rc = sqlite3_prepare_v2(handle,
            _SYSMON_DB_SQLITE_PURGE_ALERTS,
            strlen(_SYSMON_DB_SQLITE_PURGE_ALERTS) + 1,
            &purge_alerts, NULL);
        if (rc != SQLITE_OK)
            throw csSysMonDbException(rc, sqlite3_errstr(rc));
    }
    else sqlite3_reset(purge_alerts);

    // Max age
    index = sqlite3_bind_parameter_index(purge_alerts, "@max_age");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: max_age");
    if ((rc = sqlite3_bind_int64(purge_alerts,
        index, static_cast<sqlite3_int64>(age))) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    // csAF_FLG_READ
    index = sqlite3_bind_parameter_index(purge_alerts, "@csAF_FLG_READ");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: csAF_FLG_READ");
    if ((rc = sqlite3_bind_int64(purge_alerts, index,
        static_cast<sqlite3_int64>(csSysMonAlert::csAF_FLG_READ))) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    // csAF_FLG_PERSIST
    index = sqlite3_bind_parameter_index(purge_alerts, "@csAF_FLG_PERSIST");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: csAF_FLG_PERSIST");
    if ((rc = sqlite3_bind_int64(purge_alerts,
        index, static_cast<sqlite3_int64>(csSysMonAlert::csAF_FLG_PERSIST))) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));

    do {
        rc = sqlite3_step(purge_alerts);
    }
    while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

    if (rc == SQLITE_ERROR) {
        rc = sqlite3_errcode(handle);
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    }
}

void csSysMonDb_sqlite::MarkAsRead(int64_t id)
{
    int rc, index = 0;

    if (mark_read == NULL) {
        rc = sqlite3_prepare_v2(handle,
            _SYSMON_DB_SQLITE_MARK_READ,
            strlen(_SYSMON_DB_SQLITE_MARK_READ) + 1,
            &mark_read, NULL);
        if (rc != SQLITE_OK)
            throw csSysMonDbException(rc, sqlite3_errstr(rc));
    }
    else sqlite3_reset(mark_read);

    // csAF_FLG_READ
    index = sqlite3_bind_parameter_index(mark_read, "@csAF_FLG_READ");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: csAF_FLG_READ");
    if ((rc = sqlite3_bind_int64(mark_read, index,
        static_cast<sqlite3_int64>(csSysMonAlert::csAF_FLG_READ))) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));

    // ID
    index = sqlite3_bind_parameter_index(mark_read, "@id");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: id");
    if ((rc = sqlite3_bind_int64(mark_read,
        index, static_cast<sqlite3_int64>(id))) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));

    do {
        rc = sqlite3_step(mark_read);
    }
    while (rc != SQLITE_DONE && rc != SQLITE_ERROR);

    if (rc == SQLITE_ERROR) {
        rc = sqlite3_errcode(handle);
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    }
}

void csSysMonDb_sqlite::Exec(int (*callback)(void *, int, char**, char **), void *param)
{
    csLog::Log(csLog::Debug, "%s:%d: %p: %s",
        __PRETTY_FUNCTION__, __LINE__, handle, sql.str().c_str());

    char *es = NULL;
    int rc = sqlite3_exec(handle, sql.str().c_str(), callback, param, &es);
    if (rc != SQLITE_OK) {
        errstr.str("");
        errstr << es;
        sqlite3_free(es);
        throw csSysMonDbException(rc, errstr.str().c_str());
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
