"""
SUDO Responder Tests.

:requirement: sudo
"""

from __future__ import annotations

from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology

import pytest


def _setup_sudo(client: Client, provider: GenericProvider):
    if isinstance(provider, Client):
        client.sssd.common.local()

    client.sssd.authselect.select("sssd", ["with-mkhomedir", "with-sudo"])
    client.sssd.enable_responder("sudo")
    client.sssd.svc.start("oddjobd.service")


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.BareAD)
@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.topology(KnownTopology.BareLDAP)
@pytest.mark.topology(KnownTopology.BareClient)
def test_basic__single_user(client: Client, provider: GenericProvider):
    """
    :title: One user is allowed to run command, other user is not
    :setup:
        1. Create users "user-1" and "user-2"
        2. Create sudorule to allow "user-1" run /bin/ls on all hosts
        3. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo /bin/ls root" as user-1
        2. Run "sudo /bin/ls root" as user-2
    :expectedresults:
        1. User is able to run /bin/ls as root
        2. User is not able to run /bin/ls as root
    :customerscenario: False
    """

    _setup_sudo(client, provider)
    u = provider.user("user-1").add()
    u2 = provider.user("user-2").add()
    provider.sudorule("test").add(user=u, host="ALL", command="/bin/ls")
    client.sssd.restart()

    assert client.auth.sudo.run(
        u.name, "Secret123", command="/bin/ls /root"
    ), f"User {u.name} failed to run sudo with command /bin/ls!"
    assert not client.auth.sudo.run(
        u2.name, "Secret123", command="/bin/ls /root"
    ), f"User {u2.name} was able to run sudo with command /bin/ls!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.BareAD)
@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.topology(KnownTopology.BareLDAP)
@pytest.mark.topology(KnownTopology.BareClient)
def test_basic__multiple_users(client: Client, provider: GenericProvider):
    """
    :title: User from list are allowed to run a command
    :setup:
        1. Create users "user-1", "user-2" and "user-deny"
        2. Create sudorule to allow "user-1" and "user-2" run /bin/ls on all hosts
        3. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo /bin/ls root" as user-1
        2. Run "sudo /bin/ls root" as user-2
        3. Run "sudo /bin/ls root" as user-deny
    :expectedresults:
        1. User "user-1" is able to run /bin/ls as root
        2. User "user-2" is able to run /bin/ls as root
        3. User  "user-demy" is not able to run /bin/ls as root
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u1 = provider.user("user-1").add()
    u2 = provider.user("user-2").add()
    u3 = provider.user("user-deny").add()
    provider.sudorule("userlist").add(user=[u1, u2], host="ALL", command="/bin/ls")
    client.sssd.restart()
    assert client.auth.sudo.run(
        u1.name, "Secret123", command="/bin/ls /root"
    ), f"User {u1.name} failed to run sudo with command /bin/ls!"
    assert client.auth.sudo.run(
        u2.name, "Secret123", command="/bin/ls /root"
    ), f"User {u2.name} failed to run sudo with command /bin/ls!"
    assert not client.auth.sudo.run(
        u3.name, "Secret123", command="/bin/ls /root"
    ), f"User {u3.name} was able to run sudo with command /bin/ls!"


@pytest.mark.importance("critical")
@pytest.mark.contains_workaround_for(gh=4483)
@pytest.mark.topology(KnownTopology.BareAD)
@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.topology(KnownTopology.BareLDAP)
@pytest.mark.topology(KnownTopology.BareClient)
def test_basic__single_group(client: Client, provider: GenericProvider):
    """
    :title: POSIX group can be set in sudoUser attribute
    :setup:
        1. Create user "user-1"
        2. Create group "group-1" with "user-1" as a member
        3. Create sudorule to allow "group-1" run /bin/ls on all hosts
        4. Enable SSSD sudo responder
        5. Start SSSD
    :steps:
        1. List sudo rules for "user-1"
        2. Run "sudo /bin/ls" as "user-1"
    :expectedresults:
        1. User is able to run only /bin/ls
        2. Command is successful
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u = provider.user("user-1").add()
    g = provider.group("group-1").add().add_member(u)
    provider.sudorule("test").add(user=g, host="ALL", command="/bin/ls")
    client.sssd.restart()

    # Until https://github.com/SSSD/sssd/issues/4483 is resolved
    # Running 'id user-1' will resolve SIDs into group names
    if isinstance(provider, AD):
        client.tools.id(u.name)

    assert client.auth.sudo.list(
        u.name, "Secret123", expected=["(root) /bin/ls"]
    ), f"User {u.name} has not /bin/ls in allowed commands!"
    assert client.auth.sudo.run(
        u.name, "Secret123", command="/bin/ls"
    ), f"User {u.name} failed to run sudo with command /bin/ls!"


@pytest.mark.importance("critical")
@pytest.mark.contains_workaround_for(gh=4483)
@pytest.mark.topology(KnownTopology.BareClient)
def test_basic__multiple_groups(client: Client, provider: GenericProvider):
    """
    :title: Multiple POSIX groups can be set in sudoUser attribute
    :setup:
        1. Create users "user-1", "user-2" and "user-deny"
        2. Create group "group-1" with "user-1" as a member
        3. Create group "group-2" with "user-2" as a member
        3. Create sudorule to allow "group-1", "group-2" run /bin/ls on all hosts
        4. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo /bin/ls" as "user-1"
        2. Run "sudo /bin/ls" as "user-2"
        2. Run "sudo /bin/ls" as "user-deny"
    :expectedresults:
        1. User "user-1" is able to run /bin/ls
        2. User "user-2" is able to run /bin/ls
        2. User "user-deny" is not able to run /bin/ls
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u1 = provider.user("user-1").add()
    g1 = provider.group("group-1").add().add_member(u1)
    u2 = provider.user("user-2").add()
    g2 = provider.group("group-2").add().add_member(u2)
    u3 = provider.user("user-deny").add()
    provider.sudorule("test").add(user=[g1, g2], host="ALL", command="/bin/ls")
    client.sssd.restart()
    # Until https://github.com/SSSD/sssd/issues/4483 is resolved
    # Running 'id user-1' will resolve SIDs into group names
    if isinstance(provider, AD):
        client.tools.id(u1.name)
        client.tools.id(u2.name)
        client.tools.id(u3.name)

    assert client.auth.sudo.run(
        u1.name, "Secret123", command="/bin/ls /root"
    ), f"User {u1.name} failed to run sudo with command /bin/ls!"
    assert client.auth.sudo.run(
        u2.name, "Secret123", command="/bin/ls /root"
    ), f"User {u2.name} failed to run sudo with command /bin/ls!"
    assert not client.auth.sudo.run(
        u3.name, "Secret123", command="/bin/ls /root"
    ), f"User {u3.name} was able to run sudo with command /bin/ls!"


@pytest.mark.importance("critical")
@pytest.mark.contains_workaround_for(gh=4483)
@pytest.mark.topology(KnownTopology.BareAD)
@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.topology(KnownTopology.BareLDAP)
@pytest.mark.topology(KnownTopology.BareClient)
def test_basic__user_and_group(client: Client, provider: GenericProvider):
    """
    :title: POSIX groups and users can be mixed in user
    :setup:
        1. Create user "user-1" and "user-2"
        2. Create group "group-1" with "user-1" as a member
        3. Create sudorule to allow "group-1" and "user-2" run /bin/ls on all hosts
        4. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo /bin/ls" as "user-1"
        2. Run "sudo /bin/ls" as "user-2"
    :expectedresults:
        1. User "user-1" is able to run only /bin/ls
        2. User "user-2" is able to run only /bin/ls
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u1 = provider.user("user-1").add()
    u2 = provider.user("user-2").add()
    g = provider.group("group-1").add().add_member(u1)
    provider.sudorule("test").add(user=[g, u2], host="ALL", command="/bin/ls")
    client.sssd.restart()
    # Until https://github.com/SSSD/sssd/issues/4483 is resolved
    # Running 'id user-1' will resolve SIDs into group names
    if isinstance(provider, AD):
        client.tools.id(u1.name)
        client.tools.id(u2.name)

    assert client.auth.sudo.run(
        u1.name, "Secret123", command="/bin/ls /root"
    ), f"User {u1.name} failed to run sudo with command /bin/ls!"
    assert client.auth.sudo.run(
        u2.name, "Secret123", command="/bin/ls /root"
    ), f"User {u2.name} failed to run sudo with command /bin/ls!"


@pytest.mark.importance("critical")
@pytest.mark.contains_workaround_for(gh=4483)
@pytest.mark.topology(KnownTopology.BareAD)
@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.topology(KnownTopology.BareLDAP)
@pytest.mark.topology(KnownTopology.BareClient)
def test_basic__multiple_commands(client: Client, provider: GenericProvider):
    """
    :title: Multiple commands can be set in sudo rule
    :setup:
        1. Create user "user-1"
        2. Create sudorule to allow "user-1" run /bin/ls and /bin/df
        3. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo /bin/ls" as "user-1"
        2. Run "sudo /bin/df" as "user-1"
    :expectedresults:
        1. User "user-1" is able to run /bin/ls
        2. User "user-1" is able to run /bin/df
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u = provider.user("user-1").add()
    provider.sudorule("test").add(user=u, host="ALL", command=["/bin/ls", "/bin/df"])
    client.sssd.restart()

    # Until https://github.com/SSSD/sssd/issues/4483 is resolved
    # Running 'id user-1' will resolve SIDs into group names
    if isinstance(provider, AD):
        client.tools.id(u.name)

    assert client.auth.sudo.run(
        u.name, "Secret123", command="/bin/ls /root"
    ), f"User {u.name} failed to run sudo with command /bin/ls!"
    assert client.auth.sudo.run(
        u.name, "Secret123", command="/bin/df"
    ), f"User {u.name} failed to run sudo with command /bin/df!"


@pytest.mark.importance("critical")
@pytest.mark.contains_workaround_for(gh=4483)
@pytest.mark.topology(KnownTopology.BareAD)
@pytest.mark.topology(KnownTopology.BareLDAP)
@pytest.mark.topology(KnownTopology.BareClient)
def test_basic__excluded_command(client: Client, provider: GenericProvider):
    """
    :title: Excluded command can be set in sudo rule
    :setup:
        1. Create user "user-1"
        2. Create sudorule to allow "user-1" run ALL excluding /bin/df
        3. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo /bin/ls" as "user-1"
        2. Run "sudo /bin/df" as "user-1"
    :expectedresults:
        1. User "user-1" is able to run /bin/ls
        2. User "user-1" is not able to run /bin/df
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u = provider.user("user-1").add()

    provider.sudorule("test").add(user=u, host="ALL", command=["ALL", "!/bin/df"])
    client.sssd.restart()
    # Until https://github.com/SSSD/sssd/issues/4483 is resolved
    # Running 'id user-1' will resolve SIDs into group names
    if isinstance(provider, AD):
        client.tools.id(u.name)

    assert client.auth.sudo.run(
        u.name, "Secret123", command="/bin/ls /root"
    ), f"User {u.name} failed to run sudo with command /bin/ls!"
    assert not client.auth.sudo.run(
        u.name, "Secret123", command="/bin/df"
    ), f"User {u.name} was able to run sudo with command /bin/df!"


@pytest.mark.importance("critical")
@pytest.mark.contains_workaround_for(gh=4483)
@pytest.mark.topology(KnownTopology.BareAD)
@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.topology(KnownTopology.BareLDAP)
@pytest.mark.topology(KnownTopology.BareClient)
def test_basic__single_runasuser(client: Client, provider: GenericProvider):
    """
    :title: Command can be run as another user
    :setup:
        1. Create user "user-1", "user-2" and "user-3"
        3. Create sudorule to allow "user-1" run as "user-2" run whoami
        4. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo -u user-2 whoami" as "user-1"
        2. Run "sudo -u user-3 whoami" as "user-1"
    :expectedresults:
        1. User "user-1" is able to run the command as "user-2"
        2. User "user-1" is not able to run the command as "user-3"
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u1 = provider.user("user-1").add()
    u2 = provider.user("user-2").add()
    u3 = provider.user("user-3").add()
    provider.sudorule("test").add(user=u1, host="ALL", runasuser=u2, command="/usr/bin/whoami")
    client.sssd.restart()
    # Until https://github.com/SSSD/sssd/issues/4483 is resolved
    # Running 'id user-1' will resolve SIDs into group names
    if isinstance(provider, AD):
        client.tools.id(u1.name)
        client.tools.id(u2.name)
        client.tools.id(u3.name)

    assert (
        client.auth.sudo.run_advanced(u1.name, "Secret123", parameters=["-u", u2.name], command="whoami").rc == 0
    ), f"User {u1.name} failed to run sudo with command whoami as {u2.name}!"
    assert (
        not client.auth.sudo.run_advanced(u1.name, "Secret123", parameters=["-u", u3.name], command="whoami").rc == 0
    ), f"User {u1.name} was able to run sudo with command whoami as {u3.name}!"


@pytest.mark.importance("critical")
@pytest.mark.contains_workaround_for(gh=4483)
@pytest.mark.ticket(bz=1910131)
@pytest.mark.topology(KnownTopology.BareAD)
@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.topology(KnownTopology.BareLDAP)
@pytest.mark.topology(KnownTopology.BareClient)
def test_basic__multiple_runasuser(client: Client, provider: GenericProvider):
    """
    :title: Multiple runasuser can be set in sudo rule
    :setup:
        1. Create user "user-1", "user-2" and "user-3"
        3. Create sudorule to allow "user-1" run as "user-2" or "user-3" run whoami
        4. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo -u user-2 whoami" as "user-1"
        2. Run "sudo -u user-3 whoami" as "user-1"
    :expectedresults:
        1. User "user-1" is able to run the command as "user-2"
        2. User "user-1" is able to run the command as "user-3"
    :customerscenario: True
    """
    _setup_sudo(client, provider)
    u1 = provider.user("user-1").add()
    u2 = provider.user("user-2").add()
    u3 = provider.user("user-3").add()
    provider.sudorule("test").add(user=u1, host="ALL", runasuser=[u2, u3], command="/usr/bin/whoami")
    client.sssd.restart()
    # Until https://github.com/SSSD/sssd/issues/4483 is resolved
    # Running 'id user-1' will resolve SIDs into group names
    if isinstance(provider, AD):
        client.tools.id(u1.name)
        client.tools.id(u2.name)
        client.tools.id(u3.name)

    assert (
        client.auth.sudo.run_advanced(u1.name, "Secret123", parameters=["-u", u2.name], command="whoami").rc == 0
    ), f"User {u1.name} failed to run sudo with command whoami as {u2.name}!"
    assert (
        client.auth.sudo.run_advanced(u1.name, "Secret123", parameters=["-u", u3.name], command="whoami").rc == 0
    ), f"User {u1.name} failed to run sudo with command whoami as {u3.name}!"


@pytest.mark.importance("critical")
@pytest.mark.contains_workaround_for(gh=4483)
@pytest.mark.topology(KnownTopology.BareClient)
def test_basic__single_runasgroup(client: Client, provider: GenericProvider):
    """
    :title: Command can be run as another group
    :setup:
        1. Create user "user-1"
        3. Create sudorule to allow "user-1" run as "group-1" run whoami
        4. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo -g group-1 whoami" as "user-1"
        2. Run "sudo -g group-2 whoami" as "user-1"
    :expectedresults:
        1. User "user-1" is able to run the command as "group-1"
        2. User "user-1" is not able to run the command as "group-2"
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u1 = provider.user("user-1").add()
    g1 = provider.group("group-1").add()
    g2 = provider.group("group-2").add()
    provider.sudorule("test").add(user=u1, host="ALL", runasgroup=g1, command="/usr/bin/whoami")
    client.sssd.restart()

    assert (
        client.auth.sudo.run_advanced(u1.name, "Secret123", parameters=["-g", g1.name], command="whoami").rc == 0
    ), f"User {u1.name} failed to run sudo with command whoami as {g1.name}!"
    assert (
        not client.auth.sudo.run_advanced(u1.name, "Secret123", parameters=["-g", g2.name], command="whoami").rc == 0
    ), f"User {u1.name} was able to run sudo with command whoami as {g2.name}!"


@pytest.mark.importance("critical")
@pytest.mark.contains_workaround_for(gh=4483)
@pytest.mark.topology(KnownTopology.BareClient)
def test_basic__multiple_runasgroup(client: Client, provider: GenericProvider):
    """
    :title: Command can be run as another group from list
    :setup:
        1. Create user "user-1"
        3. Create sudorule to allow "user-1" run as "group-1, group-2" run whoami
        4. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo -g group-1 whoami" as "user-1"
        2. Run "sudo -g group-2 whoami" as "user-1"
        3. Run "sudo -g group-3 whoami" as "user-1"
    :expectedresults:
        1. User "user-1" is able to run the command as "group-1"
        2. User "user-1" is able to run the command as "group-2"
        3. User "user-1" is not able to run the command as "group-3"
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u1 = provider.user("user-1").add()
    g1 = provider.group("group-1").add()
    g2 = provider.group("group-2").add()
    g3 = provider.group("group-3").add()
    provider.sudorule("test").add(user=u1, host="ALL", runasgroup=[g1, g2], command="/usr/bin/whoami")
    client.sssd.restart()

    assert (
        client.auth.sudo.run_advanced(u1.name, "Secret123", parameters=["-g", g1.name], command="whoami").rc == 0
    ), f"User {u1.name} failed to run sudo with command whoami as {g1.name}!"
    assert (
        client.auth.sudo.run_advanced(u1.name, "Secret123", parameters=["-g", g2.name], command="whoami").rc == 0
    ), f"User {u1.name} failed to run sudo with command whoami as {g2.name}!"
    assert (
        not client.auth.sudo.run_advanced(u1.name, "Secret123", parameters=["-g", g3.name], command="whoami").rc == 0
    ), f"User {u1.name} was able to run sudo with command whoami as {g3.name}!"


@pytest.mark.importance("critical")
@pytest.mark.contains_workaround_for(gh=4483)
@pytest.mark.topology(KnownTopology.BareClient)
def test_basic__runasuser_and_runasgroup(client: Client, provider: GenericProvider):
    """
    :title: Command can be run as another group or user
    :setup:
        1. Create user "user-1" and "user-2"
        3. Create sudorule to allow "user-1" run as "group-1, user-2" run whoami
        4. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo -u user-2 -g group-1 whoami" as "user-1"
    :expectedresults:
        1. User "user-1" is able to run the command as "user-2" and "group-1"
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u1 = provider.user("user-1").add()
    u2 = provider.user("user-2").add()
    g1 = provider.group("group-1").add()

    provider.sudorule("test").add(user=u1, host="ALL", runasuser=u2, runasgroup=g1, command="/usr/bin/whoami")
    client.sssd.restart()

    assert (
        client.auth.sudo.run_advanced(
            u1.name, "Secret123", parameters=["-u", u2.name, "-g", g1.name], command="whoami"
        ).rc
        == 0
    ), f"User {u1.name} failed to run sudo with command whoami as {u2.name} and {g1.name}!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.BareAD)
@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.topology(KnownTopology.BareLDAP)
@pytest.mark.topology(KnownTopology.BareClient)
@pytest.mark.parametrize(
    "name",
    [
        "shortname",
        "fqdn",
        # "wildcard_shortname",
        # "wildcard_fqdn"
    ],
)
def test_basic__hostname_hostname(client: Client, provider: GenericProvider, name: str):
    """
    :title: Sudo rules work with various hostname formats
    :setup:
        1. Create user "user-1"
        2. Create sudorule to allow "user-1" run /bin/ls on matching hostname
        3. Create sudorule to allow "user-1" run /bin/df on different hostname
        4. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo /bin/ls /root" as user-1
        2. Run "sudo /bin/df" as user-1
    :expectedresults:
        1. User is able to run /bin/ls as root
        2. User is not able to run /bin/df as root
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u = provider.user("user-1").add()
    other_host = "other"

    if name == "shortname":
        allowed_host = client.host.hostname.split(".")[0]
    elif name == "fqdn":
        allowed_host = client.host.hostname
        other_host = "other.test"
    elif name == "wildcard_shortname":
        allowed_host = f"*{client.host.hostname.split(".")[0][2:]}"
    elif name == "wildcard_fqdn":
        allowed_host = f"*{client.host.hostname[2:]}"
    else:
        raise ValueError(f"Invalid hostname type: {name}")

    provider.sudorule("test1").add(user=u, host=allowed_host, command="/bin/ls")
    provider.sudorule("test2").add(user=u, host=other_host, command="/bin/df")
    client.sssd.restart()

    assert client.auth.sudo.run(u.name, "Secret123", command="/bin/ls /root"), (
        f"{name}: User {u.name} was unable to run 'sudo /bin/ls /root' "
        f"that should have been allowed on {allowed_host}."
    )
    assert not client.auth.sudo.run(
        u.name, "Secret123", command="/bin/df"
    ), f"{name}: User {u.name} was able to run 'sudo /bin/df' that should have been blocked!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.BareAD)
# @pytest.mark.topology(KnownTopology.BareIPA) # IPA does not allow ip addresses for sudo rules
@pytest.mark.topology(KnownTopology.BareLDAP)
@pytest.mark.topology(KnownTopology.BareClient)
@pytest.mark.parametrize("name", ["ipv4", "ipv6"])
def test_basic__hostname_ip(client: Client, provider: GenericProvider, name: str):
    """
    :title: Sudo rules work with various ip address formats
    :setup:
        1. Create user "user-1"
        2. Create sudorule to allow "user-1" run /bin/ls on matching ip address
        3. Create sudorule to allow "user-1" run /bin/df on different ip address
        4. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo /bin/ls /root" as user-1
        2. Run "sudo /bin/df" as user-1
    :expectedresults:
        1. User is able to run /bin/ls as root
        2. User is not able to run /bin/df as root
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u = provider.user("user-1").add()

    # Grab the first interface name from the default route
    res = client.host.conn.run("ip -o -4 route show to default")

    # If the command failed, use eth0 as the interface name
    device_name = "eth0"
    if res.rc == 0:
        try:
            dev = res.stdout.split()[4].strip()
            device_name = dev
        except IndexError:
            pass

    if name == "ipv4":
        allowed_host = client.net.ip(name=device_name).address
        other_host = "10.20.30.40"
    elif name == "ipv6":
        _, allowed_host = client.net.ip(name=device_name).addresses
        other_host = "::2"
    else:
        raise ValueError(f"Invalid IP address type: {name}")
    # TODO: Add support network/netmasks, netgroup

    provider.sudorule("test1").add(user=u, host=allowed_host, command="/bin/ls")
    provider.sudorule("test2").add(user=u, host=other_host, command="/bin/df")
    client.sssd.restart()

    assert client.auth.sudo.run(u.name, "Secret123", command="/bin/ls /root"), (
        f"{name}: User {u.name} was unable to run 'sudo /bin/ls /root' "
        f"that should have been allowed on {allowed_host}."
    )
    assert not client.auth.sudo.run(
        u.name, "Secret123", command="/bin/df"
    ), f"{name}: User {u.name} was able to run 'sudo /bin/df' that should have been blocked!"


@pytest.mark.importance("high")
@pytest.mark.skip(reason="TODO: Figure out if this is a bug wrong documentation")
# LDAP base backends do not allow any negations
@pytest.mark.topology(KnownTopology.BareClient)
@pytest.mark.parametrize("name", ["shortname", "fqdn"])
def test_basic__hostname_excluded(client: Client, provider: GenericProvider, name: str):
    """
    :title: User is not allowed to run command on excluded host
    :setup:
        1. Create user "user-1"
        2. Create sudorule to allow "user-1" run /bin/ls except on excluded host
        3. Create sudorule to allow "user-1" run /bin/df with different excluded host
        4. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo /bin/ls /root" as user-1
        2. Run "sudo /bin/df" as user-1
    :expectedresults:
        1. User is not able to run /bin/ls as root
        2. User is able to run /bin/df as root
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u = provider.user("user-1").add()
    other_host = "other"

    if name == "shortname":
        excluded_host = client.host.hostname.split(".")[0]
    elif name == "fqdn":
        excluded_host = client.host.hostname
        other_host = "other.test"
    else:
        raise ValueError(f"Invalid hostname type: {name}")

    provider.sudorule("test1").add(user=u, host=f"!{excluded_host}", command="/bin/ls")
    provider.sudorule("test2").add(user=u, host=f"!{other_host}", command="/bin/df")
    client.sssd.restart()

    assert not client.auth.sudo.run(
        u.name, "Secret123", command="/bin/ls /root"
    ), f"{name}: User {u.name} was able to run 'sudo /bin/ls /root' that should have been blocked!"
    assert client.auth.sudo.run(
        u.name, "Secret123", command="/bin/df"
    ), f"{name}: User {u.name} was unable to run 'sudo /bin/df' that should have been allowed!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.BareAD)
@pytest.mark.topology(KnownTopology.BareLDAP)
@pytest.mark.topology(KnownTopology.BareClient)
@pytest.mark.parametrize("name", ["localhost", "127.0.0.1", "::1"])
def test_basic__hostname_localhost(client: Client, provider: GenericProvider, name: str):
    """
    :title: User is not allowed to run command on variations of "localhost"
    :setup:
        1. Create user "user-1"
        2. Create sudorule to allow "user-1" run /bin/ls on localhost
        4. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo /bin/ls /root" as user-1
    :expectedresults:
        1. User is not able to run /bin/ls as root
    :customerscenario: False
    """
    _setup_sudo(client, provider)
    u = provider.user("user-1").add()
    provider.sudorule("test1").add(user=u, host=name, command="/bin/ls")
    client.sssd.restart()

    assert not client.auth.sudo.run(
        u.name, "Secret123", command="/bin/ls /root"
    ), f"{name}: User {u.name} was able to run 'sudo /bin/ls /root' that should have been blocked!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.BareAD)
@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.topology(KnownTopology.BareLDAP)
@pytest.mark.topology(KnownTopology.BareClient)
def test_basic__tags_nopasswd(client: Client, provider: GenericProvider):
    """
    :title: User is allowed to run command without password
    :setup:
        1. Create users "user-1"
        2. Create sudorule to allow "user-1" run /bin/ls without password
        2. Create sudorule to allow "user-1" run /bin/df with password required
        3. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "sudo /bin/ls root" as user-1
        2. Run "sudo /bin/df" as user-1
    :expectedresults:
        1. User is able to run /bin/ls without password
        2. User is not able to run /bin/df without password
    :customerscenario: False
    """

    _setup_sudo(client, provider)
    u = provider.user("user-1").add()
    provider.sudorule("test").add(user=u, host="ALL", command="/bin/ls", nopasswd=True)
    provider.sudorule("test2").add(user=u, host="ALL", command="/bin/df")
    client.sssd.restart()

    assert client.auth.sudo.run(
        u.name, command="/bin/ls /root"
    ), f"User {u.name} was unable to run 'sudo /bin/ls /root' that should have been allowed!"
    assert not client.auth.sudo.run(
        u.name, command="/bin/df"
    ), f"User {u.name} was able to run 'sudo /bin/df' that should have been blocked!"
