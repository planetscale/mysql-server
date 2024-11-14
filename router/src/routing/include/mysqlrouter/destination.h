/*
  Copyright (c) 2020, 2024, Oracle and/or its affiliates.

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

#ifndef MYSQLROUTER_DESTINATION_INCLUDED
#define MYSQLROUTER_DESTINATION_INCLUDED

#include <list>          // list
#include <memory>        // unique_ptr
#include <string>        // string
#include <system_error>  // error_code

#include "mysql/harness/destination.h"
#include "mysqlrouter/datatypes.h"  // ServerMode
#include "routing_guidelines/routing_guidelines.h"

/**
 * Destination to forward client connections to.
 *
 * It is used between the DestinationManager implementations and MySQLRouting
 */
class Destination {
 public:
  Destination(
      mysql_harness::Destination dest,
      routing_guidelines::Server_info server_info,
      std::string routing_guidelines_route_name,
      const std::optional<bool> connection_sharing_allowed = std::nullopt)
      : dest_(std::move(dest)), server_info_(std::move(server_info)) {
    guidelines_route_info_.route_name =
        std::move(routing_guidelines_route_name);
    guidelines_route_info_.connection_sharing_allowed =
        connection_sharing_allowed;
  }

  Destination() = default;
  Destination(const Destination &) = default;
  Destination &operator=(const Destination &) = default;
  Destination(Destination &&) = default;
  Destination &operator=(Destination &&) = default;
  virtual ~Destination() = default;

  struct Guidelines_route_info {
    std::optional<bool> connection_sharing_allowed;
    std::string route_name;
  };

  const mysql_harness::Destination &destination() const {
    return dest_.value();
  }

  /**
   * Get server UUID.
   */
  const std::string &server_uuid() const { return server_info_.uuid; }

  /**
   * Get server information.
   */
  const routing_guidelines::Server_info &get_server_info() const {
    return server_info_;
  }

  /**
   * Get name of the route that was used to reach this destination.
   *
   * @return route name
   */
  const std::string &route_name() const {
    return guidelines_route_info_.route_name;
  }

  /**
   * Set name of the route that was used to reach this destination.
   *
   * @param name route name
   */
  void set_route_name(std::string name) {
    guidelines_route_info_.route_name = std::move(name);
  }

  /**
   * server-mode of the destination.
   *
   * may be: unavailable, read-only or read-write.
   */
  virtual mysqlrouter::ServerMode server_mode() const;

  const Guidelines_route_info &guidelines_route_info() const {
    return guidelines_route_info_;
  }

  /**
   * emplace a Destination at the back of the container.
   */
  template <class... Args>
  auto emplace_back(Args &&...args) {
    return destinations_.emplace_back(std::forward<Args>(args)...);
  }

  void push_back(value_type &&v) { destinations_.push_back(std::move(v)); }

  /**
   * check if destination container is empty.
   *
   * @retval true if container is empty.
   */
  bool empty() const { return destinations_.empty(); }

  /**
   * clear all values.
   */
  void clear() { destinations_.clear(); }

  /**
   * number of destinations.
   */
  size_type size() const { return destinations_.size(); }

  /**
   * Check if we already used the primaries and don't want to fallback.
   *
   * @retval true primaries already used
   * @retval false primaries are not yet used
   */
  bool primary_already_used() const { return primary_already_used_; }

  /**
   * Mark that the primary destinations are already used.
   *
   * @param p true if PRIMARY destinations are already used.
   */
  void primary_already_used(const bool p) { primary_already_used_ = p; }

  /**
   * Check if destinations are primary destinations.
   *
   * @retval true destinations are primary destinations.
   * @retval false destinations are secondary destinations.
   */
  bool is_primary_destination() const { return is_primary_destination_; }

  /**
   * Mark that the destinations are primary destinations.
   *
   * @param p true if desitnations are PRIMARY destinations.
   */
  void set_is_primary_destination(const bool p) { is_primary_destination_ = p; }

 private:
  std::optional<mysql_harness::Destination> dest_;
  routing_guidelines::Server_info server_info_{};
  Guidelines_route_info guidelines_route_info_;
};

#endif
