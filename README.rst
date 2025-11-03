=============
os-net-config
=============

A declarative network configuration tool for hosts.

Overview
--------

``os-net-config`` is a host network configuration tool which supports multiple
backend configuration providers. One of: ifcfg (network-init-scripts), 
nmstate (NetworkManager), or eni (basic support for /etc/network/interfaces)

Features
--------

The core aim of this project is to allow fine grained (but extendable)
configuration of the networking parameters for a network host. The
project consists of:

* A CLI (os-net-config) which provides configuration via a YAML or JSON
  file formats.  By default os-net-config uses a YAML config file located
  at /etc/os-net-config/config.yaml. This can be customized via the
  --config-file CLI option.

* The provider used by os-net-config, which can be customized via a flag
  Try "os-net-config --help" for a list of supported PROVIDERs.

* A python library which provides configuration via an object model.

* A set of related services like os-net-config-sriov, os-net-config-sriov-bind,
  os-net-config-dcb.

* Configuration examples could be found at
  https://github.com/os-net-config/os-net-config/tree/master/etc/os-net-config/samples

Contributing
------------

See `CONTRIBUTING.rst`__.

__ https://github.com/os-net-config/os-net-config/blob/master/CONTRIBUTING.rst

Installation
------------

* RPM based
  os-net-config is part of Openstack RHEL8+, you may install it using 'sudo yum install os-net-config'

* From source code
  Use git to download source and then 'cd os-net-confg', 'python setup.py install --prefix=/usr'

License
-------

Licensed under the Apache License, Version 2.0 (the “License”); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0
