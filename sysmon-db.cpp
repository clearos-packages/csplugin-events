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

static int csSysMonDb_sqlite_maxid(void *param, int argc, char **argv, char **colname)
{
    uint32_t *max_id = static_cast<uint32_t *>(param);

    if (max_id == NULL) return 0;
    if (argc != 1) return 0;
    if (strcmp(colname[0], "max_id")) return 0;
    if (argv[0] != NULL) *max_id = (uint32_t)atoi(argv[0]);

    return 0;
}

static int csSysMonDb_sqlite_exec(void *param, int argc, char **argv, char **colname)
{
    for (int i = 0; i < argc; i++) {
        csLog::Log(csLog::Debug, "%s = %s", colname[i], argv[i] ? argv[i] : "(null)");
    }
    return 0;
}

csSysMonDb_sqlite::csSysMonDb_sqlite(const string &db_filename)
    : csSysMonDb(csDBT_SQLITE), handle(NULL), insert_alert(NULL),
    purge_alerts(NULL), db_filename(db_filename)
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
}

void csSysMonDb_sqlite::Create(void)
{
    sql.str("");
    sql << _SYSMON_DB_SQLITE_CREATE_ALERT;
    Exec();
    sql.str("");
    sql << _SYSMON_DB_SQLITE_CREATE_GROUP;
    Exec();
}

uint32_t csSysMonDb_sqlite::GetMaxId(void)
{
//    csLog::Log(csLog::Debug, "%s:%d: %p: %s",
//        __PRETTY_FUNCTION__, __LINE__, handle, sql.str().c_str());
    char *es = NULL;
    uint32_t max_id = 0;

    sql.str("");
    sql << _SYSMON_DB_SQLITE_SELECT_MAX_ID;

    int rc = sqlite3_exec(handle, sql.str().c_str(),
        csSysMonDb_sqlite_maxid, (void *)&max_id, &es);
    if (rc != SQLITE_OK) {
        errstr.str("");
        errstr << es;
        sqlite3_free(es);
        throw csSysMonDbException(rc, errstr.str().c_str());
    }

    csLog::Log(csLog::Debug, "%s:%d: %p: %d",
        __PRETTY_FUNCTION__, __LINE__, handle, max_id);

    return max_id;
}

void csSysMonDb_sqlite::SelectAlert(const csSysMonAlert &alert, off_t offset, size_t length)
{
/*
int sqlite3_get_table(
  sqlite3 *db,          // An open database
  const char *zSql,     // SQL to be evaluated
  char ***pazResult,    // Results of the query
  int *pnRow,           // Number of result rows written here
  int *pnColumn,        // Number of result columns written here
  char **pzErrmsg       // Error msg written here
);
void sqlite3_free_table(char **result);
*/
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

    // ID
    index = sqlite3_bind_parameter_index(insert_alert, "@id");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: id");
    if ((rc = sqlite3_bind_int64(insert_alert,
        index, static_cast<sqlite3_int64>(alert.GetId()))) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
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
    // UUID
    index = sqlite3_bind_parameter_index(insert_alert, "@uuid");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: uuid");
    if ((rc = sqlite3_bind_text(insert_alert, index,
        alert.GetUUIDChar(), alert.GetUUIDLength(), SQLITE_TRANSIENT)) != SQLITE_OK)
        throw csSysMonDbException(rc, sqlite3_errstr(rc));
    // Icon
    index = sqlite3_bind_parameter_index(insert_alert, "@icon");
    if (index == 0) throw csException(EINVAL, "SQL parameter missing: icon");
    if ((rc = sqlite3_bind_text(insert_alert, index,
        alert.GetIconChar(), alert.GetIconLength(), SQLITE_TRANSIENT)) != SQLITE_OK)
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

void csSysMonDb_sqlite::Exec(void)
{
//    csLog::Log(csLog::Debug, "%s:%d: %p: %s",
//        __PRETTY_FUNCTION__, __LINE__, handle, sql.str().c_str());
    char *es = NULL;
    int rc = sqlite3_exec(handle, sql.str().c_str(), csSysMonDb_sqlite_exec, NULL, &es);
    if (rc != SQLITE_OK) {
        errstr.str("");
        errstr << es;
        sqlite3_free(es);
        throw csSysMonDbException(rc, errstr.str().c_str());
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
