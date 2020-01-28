#!/usr/bin/env python3
#
# Copyright 2020 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Create configuration for BGP neighbor.

usage: configure_bgp_neighbor.py [-h] [-v] local_as neighbor_address remote_as device

positional arguments:
  local_as             local autonomous system
  neighbor_address     neighbor address
  remote_as            remote autonomous system
  device               NETCONF device (ssh://user:password@host:port)

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  print debugging messages
"""

import argparse
import urllib.parse
import sys
import logging

from ydk.services import CRUDService
from ydk.providers import NetconfServiceProvider
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_um_router_bgp_cfg \
    as xr_um_router_bgp_cfg


def configure_bgp_neighbor(router, local_as, neighbor_address, remote_as):
    """Add config data to bgp object."""
    # local AS
    as_ = router.bgp.As()
    as_.as_number = local_as

    # global address family configuration
    address_family = as_.address_families.AddressFamily()
    address_family.af_name = xr_um_router_bgp_cfg.BgpAddressFamily.vpnv4_unicast
    as_.address_families.address_family.append(address_family)

    # configure neighbor
    neighbor = as_.neighbors.Neighbor()
    neighbor.neighbor_address = neighbor_address
    neighbor.remote_as = remote_as
    neighbor.update_source = "Loopback0"
    address_family = neighbor.address_families.AddressFamily()
    address_family.af_name = xr_um_router_bgp_cfg.BgpAddressFamily.vpnv4_unicast

    # append configuration objects
    neighbor.address_families.address_family.append(address_family)
    as_.neighbors.neighbor.append(neighbor)
    router.bgp.as_.append(as_)


if __name__ == "__main__":
    """Execute main program."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", 
                        help="print debugging messages",
                        action="store_true")
    parser.add_argument("local_as",
                        help="local autonomous system")
    parser.add_argument("neighbor_address",
                        help="neighbor address")
    parser.add_argument("remote_as",
                        help="remote autonomous system")
    parser.add_argument("device",
                        help="NETCONF device (ssh://user:password@host:port)")
    args = parser.parse_args()
    device = urllib.parse.urlparse(args.device)

    # log debug messages if verbose argument specified
    if args.verbose:
        logger = logging.getLogger("ydk")
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(("%(asctime)s - %(name)s - "
                                      "%(levelname)s - %(message)s"))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # create NETCONF provider
    provider = NetconfServiceProvider(address=device.hostname,
                                      port=device.port,
                                      username=device.username,
                                      password=device.password,
                                      protocol=device.scheme)
    # create CRUD service
    crud = CRUDService()

    # BGP configuration
    router = xr_um_router_bgp_cfg.Router()
    configure_bgp_neighbor(router, int(args.local_as), args.neighbor_address, 
                           int(args.remote_as))

    # create configuration on NETCONF device
    crud.create(provider, router)

    sys.exit()
# End of script
