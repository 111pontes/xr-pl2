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
Read all data for model Cisco-IOS-XR-ip-rib-ipv4-oper.

usage: nc-read-xr-ip-rib-ipv4-oper-99-ydk.py [-h] [-v] device

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
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ip_rib_ipv4_oper \
    as xr_ip_rib_ipv4_oper
from ydk.filters import YFilter
import logging


def filter_rib(rib):
    """Add data to rib filter object."""
    vrf = rib.vrfs.Vrf()
    vrf.vrf_name = "RED"
    af = vrf.afs.Af()
    af.af_name = "IPv4"
    saf = af.safs.Saf()
    saf.saf_name = "Unicast"
    ip_rib_route_table_name = saf.ip_rib_route_table_names.IpRibRouteTableName()
    ip_rib_route_table_name.route_table_name = "default"
    route = ip_rib_route_table_name.routes.Route()

    # prefix info to read
    route.address.yfilter = YFilter.read
    route.prefix_length.yfilter = YFilter.read
    route.protocol_name.yfilter = YFilter.read
    route.metric.yfilter = YFilter.read
    route.distance.yfilter = YFilter.read
    ipv4_rib_edm_path = route.route_path.Ipv4RibEdmPath()

    # next-hop info to read
    ipv4_rib_edm_path.address.yfilter = YFilter.read
    ipv4_rib_edm_path.next_hop_vrf_name.yfilter = YFilter.read

    route.route_path.ipv4_rib_edm_path.append(ipv4_rib_edm_path)
    ip_rib_route_table_name.routes.route.append(route)
    saf.ip_rib_route_table_names.ip_rib_route_table_name.append(ip_rib_route_table_name)
    af.safs.saf.append(saf)
    vrf.afs.af.append(af)
    rib.vrfs.vrf.append(vrf)


def process_rib(rib):
    """Process data in rib object."""
    # format string for routing-table header
    show_route_header = (
        "Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path\n"
        "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area\n"
        "       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2\n"
        "       E1 - OSPF external type 1, E2 - OSPF external type 2, E - EGP\n"
        "       i - ISIS, L1 - IS-IS level-1, L2 - IS-IS level-2\n"
        "       ia - IS-IS inter area, su - IS-IS summary null, * - candidate default\n"
        "       U - per-user static route, o - ODR, L - local, G  - DAGR, l - LISP\n"
        "       A - access/subscriber, a - Application route\n"
        "       M - mobile route, r - RPL, (!) - FRR Backup path\n\n")
    # format string for local route
    show_route_local_row = "{protocol} {prefix}/{mask} is directly connected\n"
    # format string for protocol route
    show_route_protocol_row = ("{protocol} {prefix}/{mask} [{distance}/{metric}] "
                               "via {next_hop} (nexthop in vrf {vrf_name})\n")

    protocol_name = {"bgp": "B", "local": "L"}

    show_route = show_route_header

    # iterate over all routes
    for rt in (rib.vrfs.vrf[0].afs.af[0].safs.saf[0].ip_rib_route_table_names.
               ip_rib_route_table_name[0].routes.route):
        protocol = protocol_name[str(rt.protocol_name)]
        if str(rt.protocol_name) == "local":
            show_route += show_route_local_row.format(protocol=protocol,
                                                      prefix=rt.address,
                                                      mask=rt.prefix_length)
        else:
            next_hop = rt.route_path.ipv4_rib_edm_path[0].address
            vrf_name = rt.route_path.ipv4_rib_edm_path[0].next_hop_vrf_name
            show_route += show_route_protocol_row.format(protocol=protocol,
                                                         prefix=rt.address,
                                                         mask=rt.prefix_length,
                                                         distance=rt.distance,
                                                         metric=rt.metric,
                                                         next_hop=next_hop,
                                                         vrf_name=vrf_name)

    # return formated string
    return show_route.strip()


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

    rib = xr_ip_rib_ipv4_oper.Rib()  # create object
    filter_rib(rib)

    # read data from NETCONF device
    rib = crud.read(provider, rib)
    print(process_rib(rib))  # process object data

    exit()
# End of script
