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

"""
Verify BGP VRF prefix.

usage: verify_bgp_vrf.py [-h] [-v] node vrf_name address prefix_length

positional arguments:
  node           node streaming interface status
  vrf_name       VRF name
  address        prefix address
  prefix_length  prefix length

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  print debugging messages
"""

import kafka
import sys
import json
import time
import logging

from argparse import ArgumentParser

KAFKA_TOPIC = 'pipeline'
KAFKA_BOOTSTRAP_SERVER = 'localhost:9092'
VALIDATION_TIMEOUT = 60


def verify_bgp_vrf(kafka_consumer, node, vrf_name, address, prefix_length,
                     timeout=VALIDATION_TIMEOUT):
    """Verify BGP route state."""
    telemetry_encoding_path = "Cisco-IOS-XR-ip-rib-ipv4-oper:rib/vrfs/vrf/afs/af/safs/saf/ip-rib-route-table-names/ip-rib-route-table-name/routes/route"
    start_time = time.time()
    # iterate over all arriving messages
    for kafka_msg in kafka_consumer:
        msg = json.loads(kafka_msg.value.decode('utf-8'))
        # if message is operational RIB data
        if (msg["Telemetry"]["node_id_str"] == node and
                msg["Telemetry"]["encoding_path"] == telemetry_encoding_path
                and "Rows" in msg):
            for row in msg["Rows"]:
                # if intended IPv4 unicast prefix present in RIB
                if (row["Keys"]["vrf-name"] == vrf_name
                        and row["Keys"]["af-name"] == "IPv4"
                        and row["Keys"]["saf-name"] == "Unicast"
                        and row["Keys"]["route-table-name"] == "default"
                        and row["Keys"]["address"] == address
                        and row["Keys"]["prefix-length"] == prefix_length
                        and row["Content"]["protocol-name"] == "bgp"):
                    return True

        if time.time() - start_time > timeout:
            break

    return False


if __name__ == "__main__":
    """Execute main program."""
    parser = ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging messages",
                        action="store_true")
    parser.add_argument("node",
                        help="node router streaming interface status")
    parser.add_argument("vrf_name",
                        help="VRF name")
    parser.add_argument("address",
                        help="prefix address")
    parser.add_argument("prefix_length",
                        help="prefix length")
    args = parser.parse_args()

    # log debug messages if verbose argument specified
    if args.verbose:
        logger = logging.getLogger("kafka")
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(("%(asctime)s - %(name)s - "
                                      "%(levelname)s - %(message)s"))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # create kafka consumer to pipeline topic
    kafka_consumer = kafka.KafkaConsumer(KAFKA_TOPIC,
                                         bootstrap_servers=KAFKA_BOOTSTRAP_SERVER,
                                         consumer_timeout_ms=VALIDATION_TIMEOUT*1000)

    print(verify_bgp_vrf(kafka_consumer, 
                         args.node, args.vrf_name, args.address, 
                         int(args.prefix_length)))

    sys.exit()
# End of script
