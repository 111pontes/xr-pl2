#!/usr/bin/env python3
#
# Copyright 2019 Cisco Systems, Inc.
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

from ydk.services import CRUDService
from ydk.providers import NetconfServiceProvider
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ipv4_bgp_cfg \
    as xr_ipv4_bgp_cfg
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ipv4_bgp_datatypes \
    as xr_ipv4_bgp_datatypes
from ydk.types import Empty
import logging


def configure_bgp_vrf(bgp, local_as, vrf_name, route_distinguisher):
    """Add config data to bgp object."""
    # global configuration
    instance = bgp.Instance()
    instance.instance_name = "default"
    instance_as = instance.InstanceAs()
    instance_as.as_ = 0
    four_byte_as = instance_as.FourByteAs()
    four_byte_as.as_ = local_as
    four_byte_as.bgp_running = Empty()

    # vrf configuration
    vrf = four_byte_as.vrfs.Vrf()
    vrf.vrf_name = vrf_name
    vrf.vrf_global.exists = Empty()
    vrf.vrf_global.route_distinguisher.type = xr_ipv4_bgp_cfg.BgpRouteDistinguisher.as_
    as_, as_index = route_distinguisher.split(':')
    vrf.vrf_global.route_distinguisher.as_ = int(as_)
    vrf.vrf_global.route_distinguisher.as_xx = 0
    vrf.vrf_global.route_distinguisher.as_index = int(as_index)
    vrf_global_af = vrf.vrf_global.vrf_global_afs.VrfGlobalAf()
    vrf_global_af.af_name = xr_ipv4_bgp_datatypes.BgpAddressFamily.ipv4_unicast
    vrf_global_af.enable = Empty()
    vrf_global_af.connected_routes = vrf_global_af.ConnectedRoutes()
    vrf_global_af.connected_routes.default_metric = 10
    vrf.vrf_global.vrf_global_afs.vrf_global_af.append(vrf_global_af)
    four_byte_as.vrfs.vrf.append(vrf)

    # append configuration objects
    instance_as.four_byte_as.append(four_byte_as)
    instance.instance_as.append(instance_as)
    bgp.instance.append(instance)


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
    bgp = xr_ipv4_bgp_cfg.Bgp()
    configure_bgp_vrf(bgp, int(args.local_as), args.vrf_name, args.route_distinguisher)

    # create configuration on NETCONF device
    crud.create(provider, bgp)

    sys.exit()
# End of script
