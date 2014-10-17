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

class csSysMonDb
{
public:
    csSysMonDb();
    virtual ~csSysMonDb();

    enum csDbType {
        csDBT_NULL,
        csDBT_SQLITE,
    };

protected:
    csDbType type;
};

#endif // _SYSMON_DB_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
