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
Create configuration for BGP VPN telemetry.

usage: configure_bgp_vpn_telemetry.py [-h] [-v] subscription_id destination_id ipv4_address destination_port device

positional arguments:
  subscription_id      telemetry subscription id
  destination_id       telemetry destination id
  ipv4_address         collector IPv4 address
  destination_port     collector destination port
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
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_um_telemetry_model_driven_cfg \
    as xr_um_telemetry_model_driven_cfg


def configure_bgp_vpn_telemetry(telemetry, subscription_id, destination_id, ipv4_address, 
                                destination_port):
    """Add config data to telemetry object."""
    # enable model-driven telemetry
    telemetry.model_driven = telemetry.ModelDriven()
    # destination group
    destination_group = telemetry.model_driven.destination_groups.DestinationGroup()
    destination_group.destination_group_id = destination_id
    address = destination_group.address_family.ipv4.Address()
    address.address = ipv4_address
    address.port_number = destination_port
    address.protocol = address.Protocol()
    address.protocol.grpc = address.protocol.Grpc()
    address.protocol.grpc.no_tls = address.protocol.grpc.NoTls()
    address.encoding = address.Encoding()
    address.encoding.self_describing_gpb = address.encoding.SelfDescribingGpb()
    destination_group.address_family.ipv4.address.append(address)
    telemetry.model_driven.destination_groups.destination_group.append(destination_group)

    # sensor group
    sensor_group = telemetry.model_driven.sensor_groups.SensorGroup()
    sensor_group.sensor_group_id = "BGP-VPN-SENSORS"
    sensor_path = sensor_group.sensor_paths.SensorPath()
    sensor_path.sensor_path_id = "Cisco-IOS-XR-telemetry-model-driven-oper:telemetry-model-driven/subscriptions/subscription" 
    sensor_group.sensor_paths.sensor_path.append(sensor_path)
    sensor_path = sensor_group.sensor_paths.SensorPath()
    sensor_path.sensor_path_id = "Cisco-IOS-XR-ipv4-bgp-oper:bgp/instances/instance/instance-active/default-vrf/neighbors/neighbor" 
    sensor_group.sensor_paths.sensor_path.append(sensor_path)
    sensor_path = sensor_group.sensor_paths.SensorPath()
    sensor_path.sensor_path_id = "Cisco-IOS-XR-ip-rib-ipv4-oper:rib/vrfs/vrf/afs/af/safs/saf/ip-rib-route-table-names/ip-rib-route-table-name/routes/route" 
    sensor_group.sensor_paths.sensor_path.append(sensor_path)
    telemetry.model_driven.sensor_groups.sensor_group.append(sensor_group)

    # subscription
    subscription = telemetry.model_driven.subscriptions.Subscription()
    subscription.subscription_id = subscription_id
    sensor_group = subscription.sensor_groups.SensorGroup()
    sensor_group.sensor_group_id = "BGP-VPN-SENSORS"
    sensor_group.sample_interval = 5000
    subscription.sensor_groups.sensor_group.append(sensor_group) 
    destination = subscription.destinations.Destination()
    destination.destination_id = destination_id
    subscription.destinations.destination.append(destination)
    telemetry.model_driven.subscriptions.subscription.append(subscription) 


if __name__ == "__main__":
    """Execute main program."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", 
                        help="print debugging messages",
                        action="store_true")
    parser.add_argument("subscription_id",
                        help="telemetry subscription id")
    parser.add_argument("destination_id",
                        help="telemetry destination id")
    parser.add_argument("ipv4_address",
                        help="collector IPv4 address")
    parser.add_argument("destination_port",
                        help="collector destination port")
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

    # telemetry configuration
    telemetry = xr_um_telemetry_model_driven_cfg.Telemetry()
    configure_bgp_vpn_telemetry(telemetry,
                                args.subscription_id,
                                args.destination_id,
                                args.ipv4_address,
                                int(args.destination_port))

    # create configuration on NETCONF device
    crud.create(provider, telemetry)

    sys.exit()
# End of script
