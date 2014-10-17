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

#include "sysmon-conf.h"

void csSysMonConf::Reload(void)
{
    csConf::Reload();
    parser->Parse();
}

void csPluginXmlParser::ParseElementOpen(csXmlTag *tag)
{
    csSysMonConf *_conf = static_cast<csSysMonConf *>(conf);
}

void csPluginXmlParser::ParseElementClose(csXmlTag *tag)
{
    string text = tag->GetText();
    csSysMonConf *_conf = static_cast<csSysMonConf *>(conf);

    if ((*tag) == "test-tag") {
        if (!stack.size() || (*stack.back()) != "plugin")
            ParseError("unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("missing value for tag: " + tag->GetName());

        csLog::Log(csLog::Debug, "%s: %s",
            tag->GetName().c_str(), text.c_str());
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
