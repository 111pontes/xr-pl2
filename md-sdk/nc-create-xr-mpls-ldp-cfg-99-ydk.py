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
Create configuration for model Cisco-IOS-XR-mpls-ldp-cfg.

usage: nc-create-xr-mpls-ldp-cfg-99-ydk.py [-h] [-v] device

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
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_mpls_ldp_cfg \
    as xr_mpls_ldp_cfg
from ydk.types import Empty
import logging


def config_mpls_ldp(mpls_ldp):
    """Add config data to mpls_ldp object."""
    # enable LDP
    mpls_ldp.enable = Empty()
    # enable LDP on GigabitEthernet0/0/0/0
    interface = mpls_ldp.default_vrf.interfaces.Interface()
    interface.interface_name = "GigabitEthernet0/0/0/0"
    interface.enable = Empty()
    mpls_ldp.default_vrf.interfaces.interface.append(interface)
    # enable LDP on GigabitEthernet0/0/0/1
    interface = mpls_ldp.default_vrf.interfaces.Interface()
    interface.interface_name = "GigabitEthernet0/0/0/1"
    interface.enable = Empty()
    mpls_ldp.default_vrf.interfaces.interface.append(interface)


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

    mpls_ldp = xr_mpls_ldp_cfg.MplsLdp()  # create object
    config_mpls_ldp(mpls_ldp)  # add object configuration

    # create configuration on NETCONF device
    crud.create(provider, mpls_ldp)

    exit()
# End of script
