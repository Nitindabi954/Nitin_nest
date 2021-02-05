# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2019-2021 NITK Surathkal

"""Class to handles Ldp related functionalities"""

from nest.engine.dynamic_routing import run_ldpd
from nest.routing.route_daemons import RoutingDaemonBase


class Ldp(RoutingDaemonBase):
    """
    Handles Ldp related functionalities for frr.
    """

    def __init__(self, router_ns_id, interfaces, conf_dir):
        super().__init__(router_ns_id, interfaces, "ldpd", conf_dir)

    def create_basic_config(self):
        """
        Creates a file with basic configuration for ldp.
        Use base `add_to_config` directly for more complex configurations
        """
        self.add_to_config("mpls ldp")
        self.add_to_config(
            f" router-id {self.interfaces[0].address.get_addr(with_subnet=False)}"
        )
        self.add_to_config(" address-family ipv4")
        self.add_to_config(
            f"discovery transport-address {self.interfaces[0].address.get_addr(with_subnet=False)}"
        )

        for interface in self.interfaces:
            self.add_to_config(f"  interface {interface.id}")

        self.create_config()

    def run(self):
        """
        Runs the ldpd command
        """
        run_ldpd(self.router_ns_id, self.conf_file, self.pid_file)
