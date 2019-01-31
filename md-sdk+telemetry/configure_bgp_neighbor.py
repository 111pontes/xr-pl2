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

from ydk.services import CRUDService
from ydk.providers import NetconfServiceProvider
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ipv4_bgp_cfg \
    as xr_ipv4_bgp_cfg
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ipv4_bgp_datatypes \
    as xr_ipv4_bgp_datatypes
from ydk.types import Empty
import logging


def configure_bgp_neighbor(bgp, local_as, neighbor_address, remote_as):
    """Add config data to bgp object."""
    # global configuration
    instance = bgp.Instance()
    instance.instance_name = "default"
    instance_as = instance.InstanceAs()
    instance_as.as_ = 0
    four_byte_as = instance_as.FourByteAs()
    four_byte_as.as_ = local_as
    four_byte_as.bgp_running = Empty()
    global_af = four_byte_as.default_vrf.global_.global_afs.GlobalAf()
    global_af.af_name = xr_ipv4_bgp_datatypes.BgpAddressFamily.vpnv4_unicast
    global_af.enable = Empty()
    four_byte_as.default_vrf.global_.global_afs.global_af.append(global_af)

    # configure BGP neighbor
    neighbor = four_byte_as.default_vrf.bgp_entity.neighbors.Neighbor()
    neighbor.neighbor_address = neighbor_address
    neighbor.remote_as.as_xx = 0
    neighbor.remote_as.as_yy = remote_as
    neighbor.update_source_interface = "Loopback0"
    neighbor_af = neighbor.neighbor_afs.NeighborAf()
    neighbor_af.af_name = xr_ipv4_bgp_datatypes.BgpAddressFamily.vpnv4_unicast
    neighbor_af.activate = Empty()
    neighbor.neighbor_afs.neighbor_af.append(neighbor_af)
    four_byte_as.default_vrf.bgp_entity.neighbors.neighbor.append(neighbor)

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
    bgp = xr_ipv4_bgp_cfg.Bgp()
    configure_bgp_neighbor(bgp, int(args.local_as), args.neighbor_address, int(args.remote_as))

    # create configuration on NETCONF device
    crud.create(provider, bgp)

    sys.exit()
# End of script
