=============
os-net-config
=============

A declarative network configuration tool for hosts.

Overview
--------

``os-net-config`` is a host network configuration tool which supports multiple
backend configuration providers. One of: ifcfg (network-init-scripts), 
nmstate (NetworkManager), or eni (basic support for /etc/network/interfaces)

* Issues: https://github.com/os-net-config/os-net-config/issues
* Documentation: https://github.com/os-net-config/os-net-config/tree/master/doc

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

* **RPM based**
  os-net-config is available for RHEL8+ and similar distributions.

  .. code-block:: bash

     sudo dnf install os-net-config
     # or
     sudo yum install os-net-config

* **From source**
  Use git to download source and then:

  .. code-block:: bash

     git clone https://github.com/os-net-config/os-net-config.git
     cd os-net-config
     python setup.py install --prefix=/usr
     # or using pip
     pip install .

* **From PyPI**

  .. code-block:: bash

     pip install os-net-config

Community
---------

os-net-config is now maintained as an independent community project. While it was
originally developed under OpenStack governance, the project continues to evolve
as a standalone tool for declarative network configuration.

**Project Resources:**

* GitHub Organization: https://github.com/os-net-config
* Main Repository: https://github.com/os-net-config/os-net-config

**Community Participation:**

We welcome contributions from the community! Whether you're fixing bugs,
adding features, improving documentation, or helping other users, your
participation is valued and appreciated.

License
-------

Licensed under the Apache License, Version 2.0 (the “License”); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0
