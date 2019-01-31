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
Deploy BGP VPN telemetry configuration.

usage: deploy_bgp_vpn_telemetry.py [-h] [-v] FILE

positional arguments:
  vpn_telemetry_config_file_name  telemetry configuration file (JSON)

optional arguments:
  -h, --help                      show this help message and exit
  -v, --verbose                   print debugging messages
"""

import argparse
import kafka
import sys
import json
import datetime
import logging

from ydk.services import CRUDService
from ydk.providers import NetconfServiceProvider
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_telemetry_model_driven_cfg \
    as xr_telemetry_model_driven_cfg

from configure_bgp_vpn_telemetry import configure_bgp_vpn_telemetry
from verify_bgp_vpn_telemetry import verify_bgp_vpn_telemetry

KAFKA_TOPIC = 'pipeline'
KAFKA_BOOTSTRAP_SERVER = "localhost:9092"
KAFKA_TIMEOUT = 30

VALIDATION_TIMEOUT = 90

USERNAME = PASSWORD = "admin"
PLEN = 70  # output padding length
PCHAR = '.'  # output padding character

sys.dont_write_bytecode = True


def load_telemetry_config_file(telemetry_config_file_name):
    """Load telemetry configuration file (JSON)"""
    with open(telemetry_config_file_name) as telemetry_config_file:
        config = json.load(telemetry_config_file)

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


def deploy_bgp_vpn_telemetry(kafka_consumer, provider, crud, router, destination, subscription):
    """Configure and verify BGP VPN telemetry"""
    # BGP VPN telemetry configuration
    telemetry_model_driven = xr_telemetry_model_driven_cfg.TelemetryModelDriven()
    configure_bgp_vpn_telemetry(telemetry_model_driven,
                                subscription_id=subscription["id"],
                                ipv4_address=destination["ipv4_address"],
                                destination_port=destination["port"])

    # create configuration on NETCONF device
    crud.create(provider, telemetry_model_driven)

    return verify_bgp_vpn_telemetry(kafka_consumer,
                                    node=router["name"],
                                    subscription_id=subscription["id"],
                                    timeout=VALIDATION_TIMEOUT)

if __name__ == "__main__":
    """Execute main program."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging messages",
                        action="store_true")
    parser.add_argument("telemetry_config_file_name",
                        help="telemetry configuration file (JSON)")
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

    print(("{}: Loading telemetry config ".
           format(datetime.datetime.now().time()).ljust(PLEN, PCHAR)),
          end='', flush=True)
    config = load_telemetry_config_file(args.telemetry_config_file_name)
    print(" [{}]".format(format_verify_msg(True)))

    print(("{}: Initializing NETCONF and Kafka connections ".
           format(datetime.datetime.now().time()).ljust(PLEN, PCHAR)),
          end='', flush=True)
    kafka_consumer, provider, crud = init_connections(config["router"]["address"])
    print(" [{}]".format(format_verify_msg(True)))

    # deploy BGP VPN telemetry
    print(("{}: Configure BGP VPN telemetry ".
           format(datetime.datetime.now().time()).ljust(PLEN, PCHAR)),
          end='', flush=True)
    bgp_vpn_telemetry_status = deploy_bgp_vpn_telemetry(kafka_consumer, provider, crud,
                                                        config["router"],
                                                        config["destination"],
                                                        config["subscription"])
    print(" [{}]".format(format_verify_msg(bgp_vpn_telemetry_status)))

    sys.exit()
# End of script
