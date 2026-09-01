"""
visudo Tests.

:requirement: visudo
"""

from __future__ import annotations

import uuid

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.BareClient)
def test_visudo__syntax_check_valid_rule(client: Client):
    """
    :title: visudo reports no errors for a syntactically valid sudoers rule
    :setup:
        1. Write a syntactically correct sudoers rule to a temporary file
    :steps:
        1. Run visudo -c -f <file> against the file
    :expectedresults:
        1. visudo exits with rc=0
    :customerscenario: False
    """
    sudoers_file = f"/tmp/test_visudo_valid_{uuid.uuid4().hex[:8]}.sudoers"
    client.fs.write(sudoers_file, "testuser ALL=(ALL) NOPASSWD: /bin/ls\n")

    result = client.host.conn.run(f"visudo -c -f {sudoers_file}", raise_on_error=False)

    assert result.rc == 0, f"visudo reported errors on a valid rule: {result.stdout} {result.stderr}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.BareClient)
def test_visudo__syntax_check_invalid_rule(client: Client):
    """
    :title: visudo reports a parse error for a syntactically invalid sudoers rule
    :setup:
        1. Write a sudoers file with a deliberate syntax error (missing ALL= keyword)
    :steps:
        1. Run visudo -c -f <file> against the file
    :expectedresults:
        1. visudo exits with a non-zero rc and reports a parse error
    :customerscenario: False
    """
    sudoers_file = f"/tmp/test_visudo_invalid_{uuid.uuid4().hex[:8]}.sudoers"
    client.fs.write(sudoers_file, "testuser (ALL) NOPASSWD: /bin/ls\n")

    result = client.host.conn.run(f"visudo -c -f {sudoers_file}", raise_on_error=False)

    assert result.rc != 0, "visudo should have failed on an invalid rule but returned rc=0"
    assert "parse error" in result.stderr.lower() or "syntax error" in result.stderr.lower(), (
        f"Expected 'parse error' or 'syntax error' in visudo output: {result.stdout} {result.stderr}"
    )


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.BareClient)
def test_visudo__cmnd_alias_valid_syntax(client: Client):
    """
    :title: visudo accepts a valid Cmnd_Alias definition and its use in a rule
    :setup:
        1. Write a sudoers file defining a Cmnd_Alias and a rule that references it
    :steps:
        1. Run visudo -c -f <file> against the file
    :expectedresults:
        1. visudo exits with rc=0, alias definition and reference are both valid
    :customerscenario: False
    """
    sudoers_file = f"/tmp/test_visudo_alias_{uuid.uuid4().hex[:8]}.sudoers"
    client.fs.write(
        sudoers_file,
        "Cmnd_Alias NETWORK_CMDS = /sbin/ifconfig, /sbin/ip\ntestuser ALL=(root) NOPASSWD: NETWORK_CMDS\n",
    )

    result = client.host.conn.run(f"visudo -c -f {sudoers_file}", raise_on_error=False)

    assert result.rc == 0, f"visudo rejected a valid Cmnd_Alias rule: {result.stdout} {result.stderr}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.BareClient)
def test_visudo__sudoers_d_invalid_dropin_is_caught(client: Client):
    """
    :title: visudo -c catches a syntax error in a sudoers.d drop-in file
    :setup:
        1. Write a syntactically invalid rule to /etc/sudoers.d/test-visudo-invalid-<uid>
    :steps:
        1. Run visudo -c (checks /etc/sudoers and all included files)
    :expectedresults:
        1. visudo exits with a non-zero rc, reports a parse error, and references the drop-in file path
    :customerscenario: False
    """
    dropin = f"/etc/sudoers.d/test-visudo-invalid-{uuid.uuid4().hex[:8]}"
    client.fs.write(dropin, "testuser (ALL) NOPASSWD: /bin/ls\n")

    result = client.host.conn.run("visudo -c", raise_on_error=False)

    assert result.rc != 0, "visudo -c should have failed due to invalid drop-in but returned rc=0"
    assert "parse error" in result.stderr.lower() or "syntax error" in result.stderr.lower(), (
        f"Expected 'parse error' or 'syntax error' in visudo output: {result.stdout} {result.stderr}"
    )
    assert dropin in result.stderr, f"Expected visudo error to reference drop-in path '{dropin}': {result.stderr}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.BareClient)
def test_visudo__nopasswd_rule_allows_command_without_password(client: Client):
    """
    :title: A NOPASSWD sudoers rule allows the user to run the allowed command without a password
    :setup:
        1. Create a local user
        2. Write a NOPASSWD rule for /bin/whoami to /etc/sudoers.d/<username>
    :steps:
        1. Switch to the local user and run sudo -n /bin/whoami (non-interactive, no password)
    :expectedresults:
        1. Command succeeds and outputs "root"
    :customerscenario: False
    """
    user = client.user(f"visudo-user-{uuid.uuid4().hex[:8]}").add(shell="/bin/bash")
    client.sudorule(user.name).add(user=user, command="/bin/whoami", nopasswd=True, runasuser="root")

    result = client.host.conn.run(f"su -s /bin/bash -c 'sudo -n /bin/whoami' {user.name}", raise_on_error=False)

    assert result.rc == 0, f"sudo whoami failed for {user.name}: {result.stderr}"
    assert "root" in result.stdout, f"Expected 'root' in output, got: {result.stdout!r}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.BareClient)
def test_visudo__command_negation_denies_specific_command(client: Client):
    """
    :title: A negated command in sudoers prevents the user from running that specific command
    :setup:
        1. Create a local user
        2. Write a rule granting ALL commands except /bin/sh to /etc/sudoers.d/<username>
    :steps:
        1. Switch to the local user and run sudo -n /bin/whoami (allowed)
        2. Switch to the local user and run sudo -n /bin/sh (negated, denied)
    :expectedresults:
        1. /bin/whoami succeeds and outputs "root"
        2. /bin/sh is rejected by sudo with a non-zero exit code and a "is not allowed to execute" message
    :customerscenario: False
    """
    user = client.user(f"visudo-user-{uuid.uuid4().hex[:8]}").add(shell="/bin/bash")
    client.sudorule(user.name).add(user=user, command=["ALL", "!/bin/sh"], nopasswd=True, runasuser="root")

    allowed = client.host.conn.run(f"su -s /bin/bash -c 'sudo -n /bin/whoami' {user.name}", raise_on_error=False)
    denied = client.host.conn.run(f"su -s /bin/bash -c 'sudo -n /bin/sh -c exit' {user.name}", raise_on_error=False)

    assert allowed.rc == 0, f"/bin/whoami should be allowed: {allowed.stderr}"
    assert "root" in allowed.stdout, f"Expected 'root' in whoami output, got: {allowed.stdout!r}"
    assert denied.rc != 0, "/bin/sh should be denied by the negation rule but succeeded"
    assert "is not allowed to execute" in denied.stderr, (
        f"Expected sudo denial message in stderr, got: {denied.stderr!r}"
    )


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.BareClient)
def test_visudo__user_alias_valid_syntax(client: Client):
    """
    :title: visudo accepts a valid User_Alias definition and its use in a rule
    :setup:
        1. Write a sudoers file defining a User_Alias and a rule that references it
    :steps:
        1. Run visudo -c -f <file> against the file
    :expectedresults:
        1. visudo exits with rc=0, User_Alias definition and rule reference are both valid
    :customerscenario: False
    """
    sudoers_file = f"/tmp/test_visudo_user_alias_{uuid.uuid4().hex[:8]}.sudoers"
    client.fs.write(
        sudoers_file,
        "User_Alias OPERATORS = alice, bob\nOPERATORS ALL=(root) NOPASSWD: /bin/ls\n",
    )

    result = client.host.conn.run(f"visudo -c -f {sudoers_file}", raise_on_error=False)

    assert result.rc == 0, f"visudo rejected a valid User_Alias rule: {result.stdout} {result.stderr}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.BareClient)
def test_visudo__runas_specific_user_restriction(client: Client):
    """
    :title: A sudoers runas restriction allows running as the specified user but denies others
    :setup:
        1. Create two local users: runner and target
        2. Write a NOPASSWD rule allowing runner to run /bin/whoami only as target
    :steps:
        1. Run sudo -u target -n /bin/whoami as runner (allowed)
        2. Run sudo -u root -n /bin/whoami as runner (denied — root not in runas list)
    :expectedresults:
        1. Command succeeds and outputs the target username
        2. sudo denies the command with a non-zero exit code
    :customerscenario: False
    """
    uid = uuid.uuid4().hex[:8]
    runner = client.user(f"runner-{uid}").add(shell="/bin/bash")
    target = client.user(f"target-{uid}").add(shell="/bin/bash")

    client.sudorule(runner.name).add(user=runner, command="/bin/whoami", nopasswd=True, runasuser=target.name)

    allowed = client.host.conn.run(
        f"su -s /bin/bash -c 'sudo -u {target.name} -n /bin/whoami' {runner.name}",
        raise_on_error=False,
    )
    denied = client.host.conn.run(
        f"su -s /bin/bash -c 'sudo -u root -n /bin/whoami' {runner.name}",
        raise_on_error=False,
    )

    assert allowed.rc == 0, f"sudo as {target.name} should be allowed for {runner.name}: {allowed.stderr}"
    assert target.name in allowed.stdout, f"Expected '{target.name}' in whoami output, got: {allowed.stdout!r}"
    assert denied.rc != 0, f"sudo as root should be denied for {runner.name} but succeeded"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.BareClient)
def test_visudo__host_alias_valid_syntax(client: Client):
    """
    :title: visudo accepts a valid Host_Alias definition and its use in a rule
    :setup:
        1. Write a sudoers file defining a Host_Alias and a rule that references it
    :steps:
        1. Run visudo -c -f <file> against the file
    :expectedresults:
        1. visudo exits with rc=0, Host_Alias definition and rule reference are both valid
    :customerscenario: False
    """
    sudoers_file = f"/tmp/test_visudo_host_alias_{uuid.uuid4().hex[:8]}.sudoers"
    client.fs.write(
        sudoers_file,
        "Host_Alias WEBSERVERS = web1, web2, 192.168.1.0/24\ntestuser WEBSERVERS=(root) NOPASSWD: /bin/ls\n",
    )

    result = client.host.conn.run(f"visudo -c -f {sudoers_file}", raise_on_error=False)

    assert result.rc == 0, f"visudo rejected a valid Host_Alias rule: {result.stdout} {result.stderr}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.BareClient)
def test_visudo__sudo_list_shows_allowed_commands(client: Client):
    """
    :title: sudo -l lists the commands allowed by a sudoers rule for a user
    :setup:
        1. Create a local user
        2. Write a NOPASSWD rule granting /bin/ls and /bin/id to the user
    :steps:
        1. Run sudo -l -U <username> as root to list the user's sudo privileges
    :expectedresults:
        1. Output lists both /bin/ls and /bin/id as allowed commands for the user
    :customerscenario: False
    """
    user = client.user(f"visudo-list-{uuid.uuid4().hex[:8]}").add(shell="/bin/bash")
    dropin = f"/etc/sudoers.d/{user.name}"
    client.fs.write(dropin, f"{user.name} ALL=(root) NOPASSWD: /bin/ls, /bin/id\n")

    result = client.host.conn.run(f"sudo -l -U {user.name}", raise_on_error=False)

    assert result.rc == 0, f"sudo -l failed for {user.name}: {result.stderr}"
    assert "/bin/ls" in result.stdout, f"Expected /bin/ls in sudo -l output: {result.stdout!r}"
    assert "/bin/id" in result.stdout, f"Expected /bin/id in sudo -l output: {result.stdout!r}"
