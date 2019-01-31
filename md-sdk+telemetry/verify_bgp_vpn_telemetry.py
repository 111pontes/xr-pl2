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
Verify BGP VPN telemetry operation.

usage: verify_bgp_vpn_telemetry.py [-h] [-v] node subscription_id

positional arguments:
  node              node streaming telemetry data
  subscription_id   telemetry subscription id

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
MAX_VALIDATION_SAMPLES = 3

def verify_bgp_vpn_telemetry(kafka_consumer, node, subscription_id,
                               max_validation_samples=MAX_VALIDATION_SAMPLES,
                               timeout=VALIDATION_TIMEOUT):
    """Verify BGP VPN telemetry operation."""
    telemetry_encoding_path = "Cisco-IOS-XR-telemetry-model-driven-oper:telemetry-model-driven/subscriptions/subscription"
    packets_sent = 0
    increasing_packets_sent = True
    validation_sample_count = 0
    start_time = time.time()
	# iterate over all arriving messages
    for kafka_msg in kafka_consumer:
        msg = json.loads(kafka_msg.value.decode('utf-8'))
		# if message is operational telemetry data
        if (msg["Telemetry"]["node_id_str"] == node and
                msg["Telemetry"]["encoding_path"] == telemetry_encoding_path
                and "Rows" in msg):
            for row in msg["Rows"]:
                if (row["Keys"]["subscription-id"] == subscription_id):
                    increasing_packets_sent &= (row["Content"]
                                                   ["subscription"]
                                                   ["destination-grps"]
                                                   ["destinations"]
                                                   ["total-num-of-packets-sent"] > packets_sent)
                    packets_sent = row["Content"]["subscription"]["destination-grps"]["destinations"]["total-num-of-packets-sent"]
                    validation_sample_count += 1
			    # if packets sent increased for the number of max_validation_samples
                if (increasing_packets_sent):
                    if (validation_sample_count == max_validation_samples):
                        return True
                else:
                    return False

        if time.time() - start_time > timeout:
            break

    return False


if __name__ == "__main__":
    """Execute main program."""
    parser = ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging messages",
                        action="store_true")
    parser.add_argument("node",
                        help="node streaming telemetry data")
    parser.add_argument("subscription_id",
                        help="telemetry subscription id")
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

    print(verify_bgp_vpn_telemetry(kafka_consumer, 
                            args.node, args.subscription_id))

    sys.exit()
# End of script
