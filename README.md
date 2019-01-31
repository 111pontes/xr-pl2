# Cisco IOS XR Programmability Lab
This lab provides hands-on experience with the programmability infrastructure in Cisco IOS XR. This new infrastructure allows you to manage a device with great flexibility in terms of models, encodings and transport options. In this lab, you will use XR native, IETF and OpenConfig YANG models to interact with NETCONF and Google RPC agents running on Cisco IOS XR. You will also use streaming telemetry, simple Python scripts and custom Ansible modules based on a model-driven SDK to enable advanced network programmability and closed-loop automation.

```
$ tree -d
.
├── ansible
│   └── ip_destination_reachable
│       └── library
├── grpc
├── md-sdk
├── md-sdk+telemetry
│   └── pipeline
├── netconf
└── yang
    └── modules
        └── cisco-ios-xr
            └── 651

12 directories
$
```
