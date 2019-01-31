#!/usr/bin/env python3
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

"""
Deploy BGP VPN service configuration.

usage: deploy_bgp_vpn_service.py [-h] [-v] FILE

positional arguments:
  vpn_config_file_name     VPN service configuration file (JSON)

optional arguments:
  -h, --help               show this help message and exit
  -v, --verbose            print debugging messages
"""

import argparse
import kafka
import sys
import json
import datetime
import logging

from ydk.services import CRUDService
from ydk.providers import NetconfServiceProvider
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ipv4_bgp_cfg \
    as xr_ipv4_bgp_cfg

from configure_bgp_neighbor import configure_bgp_neighbor
from configure_bgp_vrf import configure_bgp_vrf
from verify_bgp_neighbor import verify_bgp_neighbor
from verify_bgp_vrf import verify_bgp_vrf

KAFKA_TOPIC = 'pipeline'
KAFKA_BOOTSTRAP_SERVER = "localhost:9092"
KAFKA_TIMEOUT = 30

VALIDATION_TIMEOUT = 90

USERNAME = PASSWORD = "admin"
PLEN = 70  # output padding length
PCHAR = '.'  # output padding character

sys.dont_write_bytecode = True


def load_service_config_file(neighbor_config_file_name):
    """Load neighbor configuration file (JSON)"""
    with open(neighbor_config_file_name) as neighbor_config_file:
        config = json.load(neighbor_config_file)

    return config


def init_connections(address):
    """Initialize all connections"""
    # create kafka consumer to pipeline topic
    kafka_consumer = kafka.KafkaConsumer(KAFKA_TOPIC,
                                         bootstrap_servers=KAFKA_BOOTSTRAP_SERVER,
                                         consumer_timeout_ms=KAFKA_TIMEOUT*1000)

    # connect to LER
    provider = NetconfServiceProvider(address=address,
                                      username=USERNAME,
                                      password=PASSWORD)

    # create CRUD service
    crud = CRUDService()

    return kafka_consumer, provider, crud


def format_verify_msg(status):
    """Format validation message in color"""
    OK = '\033[92m OK \033[0m'
    FAIL = '\033[91mFAIL\033[0m'
    if status:
        return OK
    else:
        return FAIL


def deploy_bgp_neighbor(kafka_consumer, provider, crud, router, neighbor):
    """Configure and verify BGP neighbor"""
    # BGP neighbor configuration
    bgp = xr_ipv4_bgp_cfg.Bgp()
    configure_bgp_neighbor(bgp,
                           local_as=router["as"],
                           neighbor_address=neighbor["address"],
                           remote_as=neighbor["as"])

    # create configuration on NETCONF device
    crud.create(provider, bgp)

    return verify_bgp_neighbor(kafka_consumer,
                                 node=router["name"],
                                 neighbor_address=neighbor["address"],
                                 timeout=VALIDATION_TIMEOUT)


def deploy_bgp_vrf(kafka_consumer, provider, crud, router, vrf):
    """Configure and verify BGP VRF"""
    # BGP VRF configuration
    bgp = xr_ipv4_bgp_cfg.Bgp()
    configure_bgp_vrf(bgp,
                      local_as=router["as"],
                      vrf_name=vrf["name"],
                      route_distinguisher=vrf["route-distinguisher"])

    # create configuration on NETCONF device
    crud.create(provider, bgp)

    return verify_bgp_vrf(kafka_consumer,
                            node=router["name"],
                            vrf_name=vrf["name"],
                            address=vrf["prefix"]["address"],
                            prefix_length=vrf["prefix"]["length"],
                            timeout=VALIDATION_TIMEOUT)


if __name__ == "__main__":
    """Execute main program."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging messages",
                        action="store_true")
    parser.add_argument("neighbor_config_file_name",
                        help="neighbor configuration file (JSON)")
    args = parser.parse_args()

    # log debug messages if verbose argument specified
    if args.verbose:
        logger = logging.getLogger("ydk")
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(("%(asctime)s - %(name)s - "
                                      "%(levelname)s - %(message)s"))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    print(("{}: Loading BGP VPN config ".
           format(datetime.datetime.now().time()).ljust(PLEN, PCHAR)),
          end='', flush=True)
    config = load_service_config_file(args.neighbor_config_file_name)
    print(" [{}]".format(format_verify_msg(True)))

    print(("{}: Initializing NETCONF and Kafka connections ".
           format(datetime.datetime.now().time()).ljust(PLEN, PCHAR)),
          end='', flush=True)
    kafka_consumer, provider, crud = init_connections(config["router"]["address"])
    print(" [{}]".format(format_verify_msg(True)))

    # deploy BGP neighbors
    for neighbor in config["neighbors"]:
        print(("{}: Configure BGP neighbor {} ".
               format(datetime.datetime.now().time(),
                      neighbor["address"]).ljust(PLEN, PCHAR)),
              end='', flush=True)
        bgp_neighbor_status = deploy_bgp_neighbor(kafka_consumer, provider, crud,
                                                  config["router"],
                                                  neighbor)
        print(" [{}]".format(format_verify_msg(bgp_neighbor_status)))

    # deploy BGP VRFs
    for vrf in config["vrfs"]:
        print(("{}: Configure BGP VRF {} ".
               format(datetime.datetime.now().time(),
                      vrf["name"]).ljust(PLEN, PCHAR)),
              end='', flush=True)
        bgp_vrf_status = deploy_bgp_vrf(kafka_consumer, provider, crud,
                                        config["router"],
                                        vrf)
        print(" [{}]".format(format_verify_msg(bgp_vrf_status)))

    sys.exit()
# End of script
