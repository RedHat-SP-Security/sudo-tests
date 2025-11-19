"""
SUDO Responder Tests.

:requirement: sudo
"""

from __future__ import annotations
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology

import pytest


@pytest.mark.topology(KnownTopology.BareClient)
@pytest.mark.ticket(jira=["RHEL-59136", "RHEL-127359", "RHEL-127360"])
def test__env_shell_once_local(client: Client):
    """
    :title: Environment variable SHELL is not duplicated
    :setup:
        1. Create user "user-1" with shell /bin/zsh
    :steps:
        1. Run "sudo /usr/bin/env" as user-1
        2. Check if variable SHELL is present only once
    :expectedresults:
        1. Command is executed successfully
        2. Variable SHELL is present only once
    :customerscenario: True
    """
    client.host.conn.run("dnf install zsh -y")
    client.local.user("user-1").add(uid=10001, shell="/bin/zsh", password="Secret123")
    client.sssd.common.local()
    client.sssd.common.sudo()
    client.sssd.start()
    result = client.host.conn.run("sudo -iu user-1 /usr/bin/env")
    assert result.rc == 0, "Sudo command failed!"
    assert result.stdout.count("SHELL") == 1, "Variable SHELL is duplicated!"
