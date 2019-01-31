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
Verify BGP neighbor operation.

usage: verify_bgp_neighbor.py [-h] [-v] node neighbor_address

positional arguments:
  node               node streaming interface status
  neighbor_address   neighbor address

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
SESSION_STATE_ESTABLISHED = "bgp-st-estab"
VALIDATION_TIMEOUT = 60


def verify_bgp_neighbor(kafka_consumer, node, neighbor_address,
                        session_state=SESSION_STATE_ESTABLISHED,
                        timeout=VALIDATION_TIMEOUT):
    """Verify BGP session state."""
    telemetry_encoding_path = "Cisco-IOS-XR-ipv4-bgp-oper:bgp/instances/instance/instance-active/default-vrf/neighbors/neighbor"
    start_time = time.time()
    # iterate over all arriving messages
    for kafka_msg in kafka_consumer:
        msg = json.loads(kafka_msg.value.decode('utf-8'))
        # if message is operational BGP data
        if (msg["Telemetry"]["node_id_str"] == node and
                msg["Telemetry"]["encoding_path"] == telemetry_encoding_path
                and "Rows" in msg):
            for row in msg["Rows"]:
                # if neighbor in intended session state
                if (row["Keys"]["instance-name"] == "default"
                        and row["Keys"]["neighbor-address"] == neighbor_address
                        and row["Content"]["connection-state"] == session_state):
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
    parser.add_argument("neighbor_address",
                        help="neighbor address")
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

    print(verify_bgp_neighbor(kafka_consumer, 
                            args.node, args.neighbor_address))

    sys.exit()
# End of script
