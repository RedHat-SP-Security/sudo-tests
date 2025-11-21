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
    client.user("user-1").add(uid=10001, shell="/bin/zsh", password="Secret123")
    client.sssd.common.local()
    client.sssd.common.sudo()
    client.sssd.start()
    result = client.host.conn.run("sudo -iu user-1 /usr/bin/env")
    assert result.rc == 0, "Sudo command failed!"
    assert result.stdout.count("SHELL") == 1, "Variable SHELL is duplicated!"


@pytest.mark.topology(KnownTopology.BareClient)
@pytest.mark.ticket(jira=["RHEL-128212", "RHEL-1376"])
def test__regex_in_command(client: Client):
    """
    :title: Regex in command is working
    :setup:
        1. Create user "user-1"
        2. Create a sudo rule for user-1 with whoami command
        3. Create a sudo rule for user-1 with a regex in the command
    :steps:
        1. Run a whoami command
        2. Run a command matching the regex
        3. Run a command not matching the regex
    :expectedresults:
        1. Command is executed successfully
        2. Command is executed successfully
        3. Command is not executed
    :customerscenario: True
    """
    client.user("user-1").add(uid=10001, shell="/bin/zsh", password="Secret123")
    client.sssd.common.local()
    client.sssd.common.sudo()
    client.sssd.start()
    client.sudorule("user-1-whoami").add(user="user-1", command="/usr/bin/whoami", host="ALL")
    client.sudorule("user-1-regex").add(user="user-1", command="/usr/bin/d.*", host="ALL")
    client.host.conn.run("cat /etc/sudoers.d/*")
    assert client.auth.sudo.run("user-1", "Secret123", command="/usr/bin/whoami"), "Sudo command failed!"
    assert client.auth.sudo.run("user-1", "Secret123", command="/usr/bin/df"), "Sudo command failed!"
    assert not client.auth.sudo.run("user-1", "Secret123", command="/usr/bin/wc"), "Sudo command passed!"
