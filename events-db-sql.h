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

#define _EVENTS_DB_SQLITE_CREATE_ALERT "\
CREATE TABLE IF NOT EXISTS alerts( \
    id INTEGER PRIMARY KEY AUTOINCREMENT, \
    stamp INTEGER NOT NULL, \
    flags INTEGER NOT NULL, \
    type INTEGER NOT NULL, \
    user INTEGER, \
    origin TEXT, \
    basename TEXT, \
    uuid TEXT, \
    desc TEXT NOT NULL \
);"

#define _EVENTS_DB_SQLITE_CREATE_GROUP "\
CREATE TABLE IF NOT EXISTS groups( \
    id INTEGER NOT NULL, \
    gid INTEGER NOT NULL \
);"

#define _EVENTS_DB_SQLITE_SELECT_LAST_ID "\
SELECT seq \
FROM sqlite_sequence \
WHERE name = @table_name \
;"

#define _EVENTS_DB_SQLITE_INSERT_ALERT "\
INSERT INTO alerts ( \
    stamp, \
    flags, \
    type, \
    user, \
    origin, \
    basename, \
    uuid, \
    desc \
) \
VALUES( \
    @stamp, \
    @flags, \
    @type, \
    @user, \
    @origin, \
    @basename, \
    @uuid, \
    @desc \
);"

#define _EVENTS_DB_SQLITE_PURGE_ALERTS "\
DELETE FROM alerts \
WHERE stamp < @max_age \
;"

//#define _EVENTS_DB_SQLITE_PURGE_ALERTS  "DELETE FROM alerts WHERE stamp < @max_age AND flags & @csAF_FLG_READ AND NOT flags & @csAF_FLG_PERSIST;"

#define _EVENTS_DB_SQLITE_MARK_READ "\
UPDATE alerts \
SET flags = flags | @csAF_FLG_READ \
WHERE id = @id \
;"

#define _EVENTS_DB_SQLITE_SELECT_ALERT "\
SELECT * \
FROM alerts \
"

#define _EVENTS_DB_SQLITE_SELECT_GROUP "\
SELECT * \
FROM groups \
WHERE id = @id \
"

#endif // _EVENTS_DB_SQL_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
