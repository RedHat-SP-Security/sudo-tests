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
