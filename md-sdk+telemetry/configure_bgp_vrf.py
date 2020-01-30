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
Create configuration for BGP VRF.

usage: configure_bgp_vrf.py [-h] [-v] local_as neighbor_address remote_as vrf_name route_distinguisher device

positional arguments:
  local_as             local autonomous system
  vrf_name             VRF name
  route_distinguisher  route distinguisher (as:index)
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


def configure_bgp_vrf(router, local_as, vrf_name, route_distinguisher):
    """Add config data to bgp object."""
    # local AS
    as_ = router.bgp.As()
    as_.as_number = local_as

    # vrf configuration
    vrf = as_.vrfs.Vrf()
    vrf.vrf_name = vrf_name

    vrf.rd = vrf.Rd()
    vrf.rd.two_byte_as = vrf.rd.TwoByteAs()
    as_number, index = route_distinguisher.split(':')
    vrf.rd.two_byte_as.as_number = as_number
    vrf.rd.two_byte_as.index = int(index)

    address_family = vrf.address_families.AddressFamily()
    address_family.af_name = xr_um_router_bgp_cfg.BgpAddressFamily.ipv4_unicast
    address_family.redistribute.connected = address_family.redistribute.Connected()
    address_family.redistribute.connected.metric = 10

    # append configuration objects
    vrf.address_families.address_family.append(address_family)
    as_.vrfs.vrf.append(vrf)
    router.bgp.as_.append(as_)


if __name__ == "__main__":
    """Execute main program."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", 
                        help="print debugging messages",
                        action="store_true")
    parser.add_argument("local_as",
                        help="local autonomous system")
    parser.add_argument("vrf_name",
                        help="VRF name")
    parser.add_argument("route_distinguisher",
                        help="route distinguisher (as:index)")
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
    configure_bgp_vrf(router, int(args.local_as), args.vrf_name, 
                      args.route_distinguisher)

    # create configuration on NETCONF device
    crud.create(provider, router)

    sys.exit()
# End of script
