#!/usr/bin/env python
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
Read all data for model Cisco-IOS-XR-mpls-ldp-oper.

usage: nc-read-xr-mpls-ldp-oper-10-ydk.py [-h] [-v] device

positional arguments:
  device         NETCONF device (ssh://user:password@host:port)

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  print debugging messages
"""

from argparse import ArgumentParser
from urlparse import urlparse

from ydk.services import CRUDService
from ydk.providers import NetconfServiceProvider
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_mpls_ldp_oper \
    as xr_mpls_ldp_oper
import logging


def process_mpls_ldp(mpls_ldp):
    """Process data in mpls_ldp object."""
    # format string for prefixes
    prefix_row = "{prefix}, rev {rev}\n"
    local_binding_row = "        Local binding: label: {label}\n"
    peers_row = "        Remote bindings: ({num_peers} peers)\n"
    # format string for peer header
    peer_header  = ("            Peer                Label\n"
                    "            -----------------   ---------\n")
    # format string for remote bindings
    remote_binding_row = "            {peer:19} {label}\n"

    label = {0: "ExpNull", 3: "ImpNull"}

    show_mpls_ldp_bindings = str()

    # iterate over all LDP bindings
    for binding in mpls_ldp.global_.active.default_vrf.afs.af[0].bindings.binding:
        if binding.local_label in label:
            local_label = label[binding.local_label]
        else:
            local_label = binding.local_label
        show_mpls_ldp_bindings += prefix_row.format(prefix=binding.prefix,
                                                    rev=binding.le_local_binding_revision)
        show_mpls_ldp_bindings += local_binding_row.format(label=local_label)
        show_mpls_ldp_bindings += peers_row.format(num_peers=len(binding.remote_binding))
        show_mpls_ldp_bindings += peer_header

        # iterate over all remote bindings for a given prefix
        for remote_binding in binding.remote_binding:
            if remote_binding.remote_label in label:
                remote_label = label[remote_binding.remote_label]
            else:
                remote_label = remote_binding.remote_label
            peer_ident = remote_binding.assigning_peer_ldp_ident
            peer_label_space_id = "{}:{}".format(peer_ident.lsr_id, peer_ident.label_space_id)
            show_mpls_ldp_bindings += remote_binding_row.format(peer=peer_label_space_id,
                                                                label=remote_label)

    # return formatted string
    return show_mpls_ldp_bindings.strip()


if __name__ == "__main__":
    """Execute main program."""
    parser = ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging messages",
                        action="store_true")
    parser.add_argument("device",
                        help="NETCONF device (ssh://user:password@host:port)")
    args = parser.parse_args()
    device = urlparse(args.device)

    # log debug messages if verbose argument specified
    if args.verbose:
        logger = logging.getLogger("ydk")
        logger.setLevel(logging.DEBUG)
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

    mpls_ldp = xr_mpls_ldp_oper.MplsLdp()  # create object

    # read data from NETCONF device
    mpls_ldp = crud.read(provider, mpls_ldp)
    print(process_mpls_ldp(mpls_ldp))   # process object data

    provider.close()
    exit()
# End of script
