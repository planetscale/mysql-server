/*
  Copyright (c) 2024, Oracle and/or its affiliates.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License, version 2.0,
  as published by the Free Software Foundation.

  This program is designed to work with certain software (including
  but not limited to OpenSSL) that is licensed under separate terms,
  as designated in a particular file or component or in included license
  documentation.  The authors of MySQL hereby grant you an additional
  permission to link the program and your derivative works with the
  separately licensed software that they have either included with
  the program or referenced in the documentation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "mysql/harness/destination.h"

namespace mysql_harness {

std::string TcpDestination::str() const {
  std::string out;

  auto colon_pos = hostname_.find(':');
  if (colon_pos == std::string::npos) {
    out = hostname_;  // no colon found, no need to escape it.
  } else {
    out = "[" + hostname_ + "]";
  }

  out += ":" + std::to_string(port_);

  return out;
}

std::string LocalDestination::str() const { return path(); }

std::string Destination::str() const {
  if (is_local()) return as_local().str();

  return as_tcp().str();
}

}  // namespace mysql_harness
