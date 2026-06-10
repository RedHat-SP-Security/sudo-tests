"""
SUDO Responder Tests - Group GID.

:requirement: sudo
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.BareLDAP)
def test_sudo__sudouser_with_group_gid(client: Client, provider: LDAP):
    """
    :title: sudoUser with group GID (%#GID) works via SSSD provider
    :description:
        Sudo rule with sudoUser set to group GID notation (%#GID) should work
        via SSSD provider just as it works with direct LDAP lookup.
    :setup:
        1. Create user "userallowed" with gid 20001
        2. Create group "groupallowed" with gid 20001
        3. Create user "usernotallowed" with gid 20002
        4. Create group "groupnotallowed" with gid 20002
        5. Create sudo rule with sudoUser="%#20001" allowing ALL commands
        6. Create sudo defaults with !authenticate option
        7. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo true" as userallowed (member of gid 20001)
        2. Run "sudo true" as usernotallowed (member of gid 20002)
    :expectedresults:
        1. userallowed can execute sudo (exit status 0)
        2. usernotallowed cannot execute sudo (exit status 1)
    :customerscenario: True
    """
    # Create groups with specific GIDs
    provider.group("groupallowed").add(gid=20001)
    provider.group("groupnotallowed").add(gid=20002)

    # Create users with specific GIDs matching their groups
    provider.user("userallowed").add(uid=10001, gid=20001)
    provider.user("usernotallowed").add(uid=10002, gid=20002)

    # Create sudo rule using group GID notation
    provider.sudorule("defaults").add(option="!authenticate")
    provider.sudorule("rule1").add(
        user="%#20001",  # Group GID notation
        host="ALL",
        command="ALL",
    )

    client.sssd.common.sudo()
    client.sssd.start()

    # Test user in allowed group (gid 20001)
    assert client.auth.sudo.run("userallowed", command="true"), (
        "sudoUser with group GID failed: userallowed (gid=20001) should be able to run sudo!"
    )

    # Test user NOT in allowed group (gid 20002)
    assert not client.auth.sudo.run("usernotallowed", command="true"), (
        "sudoUser with group GID failed: usernotallowed (gid=20002) should NOT be able to run sudo!"
    )


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.BareLDAP)
def test_sudo__sudouser_with_multiple_group_gids(client: Client, provider: LDAP):
    """
    :title: sudoUser supports multiple group GID entries
    :description:
        Sudo rule can have multiple sudoUser entries with different group GIDs,
        and users from any of those groups should be allowed.
    :setup:
        1. Create user1 with gid 30001
        2. Create user2 with gid 30002
        3. Create user3 with gid 30003
        4. Create sudo rule with sudoUser="%#30001" and sudoUser="%#30002"
        5. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo true" as user1 (gid 30001)
        2. Run "sudo true" as user2 (gid 30002)
        3. Run "sudo true" as user3 (gid 30003)
    :expectedresults:
        1. user1 can execute sudo
        2. user2 can execute sudo
        3. user3 cannot execute sudo
    :customerscenario: False
    """
    # Create users with different GIDs
    provider.group("group1").add(gid=30001)
    provider.group("group2").add(gid=30002)
    provider.group("group3").add(gid=30003)

    provider.user("user1").add(uid=20001, gid=30001)
    provider.user("user2").add(uid=20002, gid=30002)
    provider.user("user3").add(uid=20003, gid=30003)

    # Create sudo rule with multiple group GIDs
    provider.sudorule("defaults").add(option="!authenticate")
    provider.sudorule("multi-gid").add(
        user=["%#30001", "%#30002"],  # Two group GIDs
        host="ALL",
        command="ALL",
    )

    client.sssd.common.sudo()
    client.sssd.start()

    # Users in allowed groups
    assert client.auth.sudo.run("user1", command="true"), "user1 (gid=30001) should be allowed!"
    assert client.auth.sudo.run("user2", command="true"), "user2 (gid=30002) should be allowed!"

    # User NOT in allowed groups
    assert not client.auth.sudo.run("user3", command="true"), "user3 (gid=30003) should NOT be allowed!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.BareLDAP)
def test_sudo__sudouser_group_gid_with_group_name_mixed(client: Client, provider: LDAP):
    """
    :title: sudoUser with mixed group GID (%#GID) and group name (%group) entries
    :description:
        Sudo rule can use both group GID notation and group name notation
        in the same rule.
    :setup:
        1. Create user1 with gid 40001 in group "admingroup"
        2. Create user2 with gid 40002 in group "devgroup"
        3. Create user3 with gid 40003 in group "testgroup"
        4. Create sudo rule with sudoUser="%#40001" and sudoUser="%devgroup"
        5. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo true" as user1 (gid 40001)
        2. Run "sudo true" as user2 (in devgroup)
        3. Run "sudo true" as user3 (gid 40003, in testgroup)
    :expectedresults:
        1. user1 can execute sudo (matched by GID)
        2. user2 can execute sudo (matched by group name)
        3. user3 cannot execute sudo
    :customerscenario: False
    """
    # Create groups
    provider.group("admingroup").add(gid=40001)
    provider.group("devgroup").add(gid=40002)
    provider.group("testgroup").add(gid=40003)

    # Create users
    provider.user("user1").add(uid=30001, gid=40001)
    provider.user("user2").add(uid=30002, gid=40002)
    provider.user("user3").add(uid=30003, gid=40003)

    # Create sudo rule mixing GID and group name notation
    provider.sudorule("defaults").add(option="!authenticate")
    provider.sudorule("mixed").add(
        user=["%#40001", "%devgroup"],  # Mix GID and group name
        host="ALL",
        command="ALL",
    )

    client.sssd.common.sudo()
    client.sssd.start()

    # User matched by GID
    assert client.auth.sudo.run("user1", command="true"), "user1 should be allowed by GID!"

    # User matched by group name
    assert client.auth.sudo.run("user2", command="true"), "user2 should be allowed by group name!"

    # User not in allowed groups
    assert not client.auth.sudo.run("user3", command="true"), "user3 should NOT be allowed!"
