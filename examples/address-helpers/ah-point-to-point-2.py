# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2019-2021 NITK Surathkal

########################
# SHOULD BE RUN AS ROOT
########################
from nest.topology import *
from nest.topology.network import Network
from nest.topology.address_helper import AddressHelper

# This program emulates point to point networks that connect two hosts `h1`
# and `h2` via a router `r1`. One ping packet is sent from `h1` to `h2`, and
# the success/failure of ping is reported. This program is similar to the
# point-to-point-2.py example available in `examples/tutorial/basic-examples`,
# the only difference is that we use an address helper in this program to
# assign IPv4 addresses to interfaces instead of manually assigning them. Note
# that two packages: `Network` and `AddressHelper` are imported in this program
# (Lines 8-9 above).

##########################################################
#                   Network Topology                     #
#                                                        #
#          5mbit, 5ms -->          5mbit, 5ms -->        #
#   h1 -------------------- r1 -------------------- h2   #
#       <-- 10mbit, 100ms        <-- 10mbit, 100ms       #
#                                                        #
##########################################################

# Create two hosts `h1` and `h2`, and one router `r1`
h1 = Node("h1")
h2 = Node("h2")
r1 = Router("r1")  # Internally, `Router` API enables IP forwarding in `r1`

# Set the IPv4 address for the networks, and not the interfaces.
# We will use the `AddressHelper` later to assign addresses to the interfaces.
# Note: this example has two networks, one each on either side of `r1`.
n1 = Network("192.168.1.0/24")  # network on the left side of `r1`
n2 = Network("192.168.2.0/24")  # network on the right side of `r1`

# Connect `h1` to `r1` (left side), and then `r1` (right side) to `h2`.
# `eth1` and `eth2` are the interfaces at `h1` and `h2`, respectively.
# `etr1a` is the first interface at `r1` which connects it with `h1`
# `etr1b` is the second interface at `r1` which connects it with `h2`
(eth1, etr1a) = connect(h1, r1, network=n1)
(etr1b, eth2) = connect(r1, h2, network=n2)

# Assign IPv4 addresses to all the interfaces in the network.
AddressHelper.assign_addresses()

# Set the link attributes: `h1` --> `r1` --> `h2`
eth1.set_attributes("5mbit", "5ms")  # from `h1` to `r1`
etr1b.set_attributes("5mbit", "5ms")  # from `r1` to `h2`

# Set the link attributes: `h2` --> `r1` --> `h1`
eth2.set_attributes("10mbit", "100ms")  # from `h2` to `r1`
etr1a.set_attributes("10mbit", "100ms")  # from `r1` to `h1`

# Set default routes in `h1` and `h2` so that the packets that cannot be
# forwarded based on the entries in their routing table are sent via a
# default interface.
h1.add_route("DEFAULT", eth1)
h2.add_route("DEFAULT", eth2)

# Send a `ping` from `h1` to `h2`.
h1.ping(eth2.address)