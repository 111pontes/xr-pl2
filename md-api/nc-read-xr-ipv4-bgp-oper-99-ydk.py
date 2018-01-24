#!/usr/bin/env python3
#
# Copyright 2016 Cisco Systems, Inc.
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
Read all data for model Cisco-IOS-XR-ipv4-bgp-oper.

usage: nc-read-xr-ipv4-bgp-oper-99-ydk.py [-h] [-v] device

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
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ipv4_bgp_oper \
    as xr_ipv4_bgp_oper
from datetime import timedelta
from ydk.filters import YFilter
import logging


def filter_bgp(bgp):
    """Add data to bgp filter object."""
    # filter neighbors
    instance = bgp.instances.Instance()
    instance.instance_name = "default"
    neighbor = instance.instance_active.default_vrf.neighbors.Neighbor()
    neighbor.yfilter = YFilter.read
    instance.instance_active.default_vrf.neighbors.neighbor.append(neighbor)
    bgp.instances.instance.append(instance)


def process_bgp(bgp):
    """Process data in bgp object."""
    # format string for BGP neighbor header
    nbr_header = ("Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  "
                  "InQ OutQ  Up/Down  St/PfxRcd\n")
    # format string for BGP neighbor
    nbr_row = ("{nbr_add!s:<14} {speaker_id!s:>4} {as_!s:>5} {msg_rcvd!s:>7} "
               "{msg_sent!s:>7} {table_ver!s:>8} {in_queue!s:>4} {out_queue!s:>4} "
               "{up_down!s:>8} {st_pfxrcd!s}\n")

    bgp_st = {xr_ipv4_bgp_oper.BgpConnState.bgp_st_idle.name: "Idle",
              xr_ipv4_bgp_oper.BgpConnState.bgp_st_active.name: "Active",
              xr_ipv4_bgp_oper.BgpConnState.bgp_st_connect.name: "Connect"}

    show_bgp_summary = nbr_header

    # iterate over all BGP neighbors
    for nbr in bgp.instances.instance[0].instance_active.default_vrf.neighbors.neighbor:
        if str(nbr.connection_state) == xr_ipv4_bgp_oper.BgpConnState.bgp_st_estab.name:
            st_pfxrcd = "{!s:>10}".format(nbr.af_data[0].prefixes_accepted)
        else:
            st_pfxrcd = bgp_st[nbr.connection_state]

        up_down = timedelta(seconds=int(str(nbr.connection_established_time)))

        show_bgp_summary += nbr_row.format(nbr_add=nbr.neighbor_address,
                                           speaker_id=nbr.speaker_id,
                                           as_=nbr.remote_as,
                                           msg_rcvd=nbr.messages_received,
                                           msg_sent=nbr.messages_sent,
                                           table_ver=nbr.af_data[0].neighbor_version,
                                           in_queue=nbr.messages_queued_in,
                                           out_queue=nbr.messages_queued_out,
                                           up_down=up_down,
                                           st_pfxrcd=st_pfxrcd)

    # return formatted string
    return show_bgp_summary.strip()


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

    bgp = xr_ipv4_bgp_oper.Bgp()  # create object
    filter_bgp(bgp)  # add BGP filter details

    # read data from NETCONF device
    bgp = crud.read(provider, bgp)
    print(process_bgp(bgp))  # process object data

    exit()
# End of script
