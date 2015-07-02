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

#ifndef _EVENTS_DB_SQL_H
#define _EVENTS_DB_SQL_H

// Pragma SQL defines

#define _EVENTS_DB_SQLITE_PRAGMA_FOREIGN_KEY "\
PRAGMA \
    foreign_keys = ON \
;"

// Create SQL defines

#define _EVENTS_DB_SQLITE_CREATE_ALERTS "\
CREATE TABLE IF NOT EXISTS alerts( \
    id INTEGER PRIMARY KEY AUTOINCREMENT, \
    hash TEXT NOT NULL, \
    created INTEGER NOT NULL, \
    updated INTEGER NOT NULL, \
    flags INTEGER NOT NULL, \
    type INTEGER NOT NULL, \
    user INTEGER, \
    origin TEXT, \
    basename TEXT, \
    uuid TEXT, \
    desc TEXT NOT NULL \
);"

#define _EVENTS_DB_SQLITE_CREATE_GROUPS "\
CREATE TABLE IF NOT EXISTS groups( \
    id INTEGER NOT NULL, \
    gid INTEGER NOT NULL, \
    FOREIGN KEY (id) REFERENCES alerts(id) ON DELETE CASCADE \
);"

#define _EVENTS_DB_SQLITE_CREATE_STAMPS "\
CREATE TABLE IF NOT EXISTS stamps( \
    id INTEGER PRIMARY KEY AUTOINCREMENT, \
    aid INTEGER NOT NULL, \
    stamp INTEGER NOT NULL, \
    FOREIGN KEY (aid) REFERENCES alerts(id) ON DELETE CASCADE \
);"

#define _EVENTS_DB_SQLITE_CREATE_TYPES "\
CREATE TABLE IF NOT EXISTS types( \
    id INTEGER PRIMARY KEY AUTOINCREMENT, \
    tag TEXT NOT NULL, \
    basename TEXT NOT NULL \
);"

#define _EVENTS_DB_SQLITE_CREATE_OVERRIDES "\
CREATE TABLE IF NOT EXISTS overrides( \
    id INTEGER PRIMARY KEY AUTOINCREMENT, \
    type INTEGER NOT NULL, \
    level INTEGER NOT NULL \
);"

// Select SQL defines

#define _EVENTS_DB_SQLITE_SELECT_ALERT "\
SELECT \
    alerts.id AS id, \
    alerts.created AS created, \
    stamps.stamp AS updated, \
    alerts.flags AS flags, \
    alerts.type AS type, \
    alerts.user AS user, \
    alerts.origin AS origin, \
    alerts.basename AS basename, \
    alerts.uuid AS uuid, \
    alerts.desc AS desc \
FROM alerts, stamps \
WHERE stamps.aid = alerts.id \
"

#define _EVENTS_DB_SQLITE_SELECT_ALERT_BY_HASH "\
SELECT id \
FROM alerts \
WHERE hash = @hash \
;"

#define _EVENTS_DB_SQLITE_SELECT_GROUP "\
SELECT * \
FROM groups \
WHERE id = @id \
"

#define _EVENTS_DB_SQLITE_SELECT_LAST_ID "\
SELECT seq \
FROM sqlite_sequence \
WHERE name = @table_name \
;"

#define _EVENTS_DB_SQLITE_SELECT_TYPES "\
SELECT id, tag \
FROM types \
;"

#define _EVENTS_DB_SQLITE_SELECT_OVERRIDE "\
SELECT type, level \
FROM overrides \
WHERE type = @type \
;"

#define _EVENTS_DB_SQLITE_SELECT_OVERRIDES "\
SELECT type, level \
FROM overrides \
;"

// Insert SQL defines

#define _EVENTS_DB_SQLITE_INSERT_ALERT "\
INSERT INTO alerts ( \
    created, \
    updated, \
    hash, \
    flags, \
    type, \
    user, \
    origin, \
    basename, \
    uuid, \
    desc \
) \
VALUES ( \
    @created, \
    @updated, \
    @hash, \
    @flags, \
    @type, \
    @user, \
    @origin, \
    @basename, \
    @uuid, \
    @desc \
);"

#define _EVENTS_DB_SQLITE_INSERT_STAMP "\
INSERT INTO stamps ( \
    aid, \
    stamp \
) \
VALUES ( \
    @aid, \
    @stamp \
);"

#define _EVENTS_DB_SQLITE_INSERT_TYPE "\
INSERT INTO types ( \
    tag, \
    basename \
) \
VALUES ( \
    @tag, \
    @basename \
);"

#define _EVENTS_DB_SQLITE_INSERT_OVERRIDE "\
INSERT INTO overrides ( \
    type, \
    level \
) \
VALUES ( \
    @type, \
    @level \
);"

// Update SQL defines

#define _EVENTS_DB_SQLITE_UPDATE_ALERT "\
UPDATE alerts \
SET updated = @stamp, flags = @flags, desc = @desc \
WHERE id = @id \
;"

#define _EVENTS_DB_SQLITE_MARK_RESOLVED "\
UPDATE alerts \
SET flags = flags | @csAF_FLG_RESOLVED \
WHERE type = @type \
;"

#define _EVENTS_DB_SQLITE_UPDATE_OVERRIDE "\
UPDATE overrides \
SET level = @level \
WHERE type = @type \
;"

// Delete SQL defines

#define _EVENTS_DB_SQLITE_PURGE_ALERTS "\
DELETE FROM alerts \
WHERE updated < @max_age \
AND flags & @csAF_FLG_RESOLVED \
;"

#define _EVENTS_DB_SQLITE_PURGE_STAMPS "\
DELETE FROM stamps \
WHERE stamp < @max_age \
;"

#define _EVENTS_DB_SQLITE_DELETE_TYPE "\
DELETE FROM types \
WHERE tag = @tag \
;"

#define _EVENTS_DB_SQLITE_DELETE_OVERRIDE "\
DELETE FROM overrides \
WHERE type = @type \
;"

#endif // _EVENTS_DB_SQL_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
