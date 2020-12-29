# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2019-2020 NITK Surathkal

"""Ping command"""

from .exec import exec_exp_commands, exec_subprocess

def ping(ns_name, dest_addr):
    """
    Send a ping packet from ns_name to dest_addr
    if possible

    Parameters
    ----------
    ns_name : str
        namespace name
    dest_addr : str
        address to ping to

    Returns
    -------
    bool
        success of ping
    """
    status = exec_subprocess(f'ip netns exec {ns_name} ping -c1 -q {dest_addr}')
    return status == 0


def run_exp_ping(ns_id, destination_ip, run_time, out, err):
    """
    Run ping to extract stats

    Parameters
    ----------
    ns_id : str
        network namespace to run netperf from
    destination_ip : str
        IP address of the destination namespace
    run_time : num
        total time to run netperf for
    out : File
        temporary file to hold the stats
    err : File
        temporary file to hold any errors

    Returns
    -------
    int
        return code of the command executed
    """

    return exec_exp_commands(f'ip netns exec {ns_id} ping {destination_ip} -w {run_time} -D \
            -i 0.2', stdout=out, stderr=err)
