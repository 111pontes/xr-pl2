#!/usr/bin/env python3
#
# Copyright 2018 Cisco Systems, Inc.
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
Create configuration for model Cisco-IOS-XR-ipv4-bgp-cfg.

usage: nc-create-xr-ipv4-bgp-cfg-99-ydk.py [-h] [-v] device

positional arguments:
  device         NETCONF device (ssh://user:password@host:port)

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  print debugging messages
"""

from argparse import ArgumentParser
import urllib.parse

from ydk.services import CRUDService
from ydk.providers import NetconfServiceProvider
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ipv4_bgp_cfg \
    as xr_ipv4_bgp_cfg
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ipv4_bgp_datatypes \
    as xr_ipv4_bgp_datatypes
from ydk.types import Empty
import logging


def config_bgp(bgp):
    """Add config data to bgp object."""
    # global configuration
    instance = bgp.Instance()
    instance.instance_name = "default"
    instance_as = instance.InstanceAs()
    instance_as.as_ = 0
    four_byte_as = instance_as.FourByteAs()
    four_byte_as.as_ = 65172
    four_byte_as.bgp_running = Empty()
    global_af = four_byte_as.default_vrf.global_.global_afs.GlobalAf()
    global_af.af_name = xr_ipv4_bgp_datatypes.BgpAddressFamily.vpnv4_unicast
    global_af.enable = Empty()
    four_byte_as.default_vrf.global_.global_afs.global_af.append(global_af)

    # configure IBGP neighbor
    neighbor = four_byte_as.default_vrf.bgp_entity.neighbors.Neighbor()
    neighbor.neighbor_address = "172.16.255.2"
    neighbor.remote_as.as_xx = 0
    neighbor.remote_as.as_yy = 65172
    neighbor.update_source_interface = "Loopback0"
    neighbor_af = neighbor.neighbor_afs.NeighborAf()
    neighbor_af.af_name = xr_ipv4_bgp_datatypes.BgpAddressFamily.vpnv4_unicast
    neighbor_af.activate = Empty()
    neighbor.neighbor_afs.neighbor_af.append(neighbor_af)
    four_byte_as.default_vrf.bgp_entity.neighbors.neighbor.append(neighbor)

    # vrf RED
    vrf = four_byte_as.vrfs.Vrf()
    vrf.vrf_name = "RED"
    vrf.vrf_global.exists = Empty()
    vrf.vrf_global.route_distinguisher.type = xr_ipv4_bgp_cfg.BgpRouteDistinguisher.as_
    vrf.vrf_global.route_distinguisher.as_ = 65172
    vrf.vrf_global.route_distinguisher.as_xx = 0
    vrf.vrf_global.route_distinguisher.as_index = 0
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
    parser = ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging messages",
                        action="store_true")
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

    bgp = xr_ipv4_bgp_cfg.Bgp()  # create object
    config_bgp(bgp)  # add object configuration

    # create configuration on NETCONF device
    crud.create(provider, bgp)

    exit()
# End of script
