"""
SUDO Security CVE Tests.

:requirement: sudo
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology

# Records effective uid/gid of the mailer process (see CVE-2026-35535 repro).
_FAKE_MAILER = """#!/bin/bash

file=/tmp/mail.$$

cat > /dev/null
echo -n "Effective UID: " >>$file
id -u >>$file
echo -n "Effective GID: " >>$file
id -g >>$file
"""


@pytest.mark.ticket(jira=["RHEL-166069", "RHEL-164620", "RHEL-164621", "RHEL-166066"])
@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.BareClient)
def test_cve__mailer_escalation(client: Client):
    """
    :title: CVE-2026-35535: Privilege escalation due to failure in privilege drop calls
    :setup:
        1. Create local user "testuser" with fixed UID/GID (10001)
        2. Install /tmp/fakemailer that logs effective UID/GID to /tmp/mail.<pid>
        3. Add sudoers drop-in: mailerpath, mail_always, and PASSWD rule for /usr/bin/whoami
        4. Enable local SSSD + sudo (same stack as other BareClient sudo tests)
    :steps:
        1. Run fakemailer manually as testuser; confirm /tmp/mail.* shows testuser's UID/GID
        2. Remove mail files, run "sudo /usr/bin/whoami" as testuser
        3. Read new /tmp/mail.* and check Effective UID/GID
    :expectedresults:
        1. Manual fakemailer records non-root ids
        2. Sudo succeeds
        3. Mailer log does not show root (0); ids match testuser (vulnerability fixed)
    :customerscenario: False
    """
    username = "testuser"
    expected_uid = 10001
    expected_gid = 10001
    mailer_drop_in_path = "/etc/sudoers.d/00-cve-35535-mailer"
    client.user(username).add(uid=expected_uid, password="Secret123")

    client.fs.write("/tmp/fakemailer", _FAKE_MAILER)
    client.fs.chmod(path="/tmp/fakemailer", mode="ugo+rx")

    sudoers = (
        f"Defaults mailerpath=/tmp/fakemailer\nDefaults mail_always\n{username} ALL=(ALL) PASSWD: /usr/bin/whoami\n"
    )
    client.fs.write(mailer_drop_in_path, sudoers)
    client.fs.chmod(path=mailer_drop_in_path, mode="ugo+r")
    visudo = client.host.conn.run(f"visudo -cf {mailer_drop_in_path}")
    assert visudo.rc == 0, (
        f"visudo rejected {mailer_drop_in_path}: sudoers syntax is invalid so sudo would not load the "
        f"CVE mailer test fragment. stderr={visudo.stderr!r} stdout={visudo.stdout!r}"
    )

    client.sssd.common.local()
    client.sssd.common.sudo()
    client.sssd.start()

    client.host.conn.run("rm -f /tmp/mail.*", raise_on_error=False)
    manual = client.host.conn.run(f"su - {username} -s /bin/bash -c 'echo hello | /tmp/fakemailer'")
    assert manual.rc == 0, (
        f"Sanity step failed: running /tmp/fakemailer as {username} (pipe stdin) must succeed so the "
        f"script can create /tmp/mail.<pid>. rc={manual.rc} stderr={manual.stderr!r} stdout={manual.stdout!r}"
    )
    cat_manual = client.host.conn.run("cat /tmp/mail.* 2>/dev/null")
    assert cat_manual.rc == 0 and cat_manual.stdout.strip(), (
        f"Sanity step failed: after manual fakemailer, expected at least one /tmp/mail.* file (fakemailer "
        f"appends Effective UID/GID there). ls exited rc={cat_manual.rc}, stdout={cat_manual.stdout!r} "
        f"stderr={cat_manual.stderr!r}"
    )
    manual_mail = cat_manual.stdout.strip()
    assert f"Effective UID: {expected_uid}" in manual_mail, (
        f"Sanity step failed: fakemailer output should contain UID {expected_uid} for {username!r} "
        f"(user created with that uid). Mail file contents: {manual_mail!r}"
    )
    assert f"Effective GID: {expected_gid}" in manual_mail, (
        f"Sanity step failed: fakemailer output should contain GID {expected_gid} for {username!r} "
        f"(user created with that gid). Mail file contents: {manual_mail!r}"
    )
    client.host.conn.run("rm -f /tmp/mail.*", raise_on_error=False)

    assert client.auth.sudo.run(username, "Secret123", command="/usr/bin/whoami"), (
        f"sudo must allow {username!r} to run /usr/bin/whoami with password Secret123 (sudoers rule from "
        f"this test); otherwise the mailer is never invoked and the CVE check cannot run."
    )
    time.sleep(3)
    after = client.host.conn.run("cat /tmp/mail.* 2>/dev/null")
    client.host.conn.run("rm -f /tmp/mail.*", raise_on_error=False)
    assert after.rc == 0 and after.stdout.strip(), (
        f"After sudo whoami with Defaults mail_always, expected a new /tmp/mail.* from fakemailer. "
        f"ls exited rc={after.rc}, stdout={after.stdout!r} stderr={after.stderr!r}"
    )
    mail = after.stdout.strip()
    assert "Effective GID: 0" not in mail, (
        f"CVE-2026-35535: mailer ran with effective GID 0 (root). When fixed, fakemailer should see "
        f"{username!r}'s GID ({expected_gid}), not root. Full mail file: {mail!r}"
    )
    assert f"Effective GID: {expected_gid}" in mail, (
        f"Mail file should record {username!r}'s effective GID ({expected_gid}) after sudo invoked the "
        f"mailer; missing or wrong line. Full mail file: {mail!r}"
    )
    assert "Effective UID: 0" not in mail, (
        f"Mailer ran with effective UID 0 (root); privilege drop for the mailer child should leave "
        f"UID {expected_uid} for {username!r}. Full mail file: {mail!r}"
    )
    assert f"Effective UID: {expected_uid}" in mail, (
        f"Mail file should record {username!r}'s effective UID ({expected_uid}) after sudo invoked the "
        f"mailer; missing or wrong line. Full mail file: {mail!r}"
    )


def _local_gentime(when: datetime) -> str:
    """Generalized Time without Z/offset so parse_gentime() uses mktime()."""
    return when.strftime("%Y%m%d%H%M%S")


def _sudo_as(client: Client, username: str, command: str, *, tz: str | None = None) -> int:
    """Run sudo -n as user; optional TZ in the same environment as sudo."""
    env = f"TZ={tz} " if tz else ""
    result = client.host.conn.run(
        f'su - "{username}" -c "{env}sudo -n {command}"',
        raise_on_error=False,
    )
    return result.rc


@pytest.mark.ticket(
    jira=[
        "RHEL-267328",
        "RHEL-267329",
        "RHEL-267330",
        "RHEL-267333",
        "RHEL-267334",
        "RHEL-267337",
        "RHEL-267338",
        "RHEL-267339",
        "RHEL-267340",
        "RHEL-267341",
        "RHEL-267342",
        "RHEL-267343",
        "RHEL-267344",
        "RHEL-267345",
        "RHEL-267347",
        "RHEL-267349",
    ]
)
@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.BareClient)
def test_cve__tz_bypasses_notbefore_notafter(client: Client):
    """
    :title: CVE-2026-96512: TZ must not bypass NOTBEFORE/NOTAFTER
    :setup:
        1. Create local user "testuser"
        2. Enable local SSSD + sudo
        3. Install sudoers drop-in with expired NOTAFTER (no Z) for /usr/bin/whoami
    :steps:
        1. Run sudo -n /usr/bin/whoami without TZ
        2. Run sudo -n /usr/bin/whoami with TZ=XXX24
        3. Replace rule with future NOTBEFORE (no Z); run without TZ
        4. Run with TZ=XXX-24
    :expectedresults:
        1. Denied (rule expired under system time)
        2. Still denied (extreme TZ must not revive expired NOTAFTER)
        3. Denied (rule not yet active)
        4. Still denied (extreme TZ must not unlock future NOTBEFORE)
    :customerscenario: False
    """
    username = "testuser"
    drop_in = "/etc/sudoers.d/00-cve-96512-tz"
    command = "/usr/bin/whoami"
    client.user(username).add(uid=10001, password="Secret123")

    client.sssd.common.local()
    client.sssd.common.sudo()
    client.sssd.start()

    # NOTAFTER ~2h ago, local time (no Z): mktime path that TZ can skew when unfixed
    notafter = _local_gentime(datetime.now() - timedelta(hours=2))
    sudoers = f"{username} ALL=(ALL) NOTAFTER={notafter} NOPASSWD: {command}\n"
    client.fs.write(drop_in, sudoers)
    client.fs.chmod(path=drop_in, mode="ugo+r")
    visudo = client.host.conn.run(f"visudo -cf {drop_in}")
    assert visudo.rc == 0, f"visudo rejected {drop_in}: stderr={visudo.stderr!r} stdout={visudo.stdout!r}"

    assert _sudo_as(client, username, command) != 0, (
        f"Sanity: NOTAFTER={notafter} is ~2h in the past; sudo -n {command} as {username!r} "
        f"must be denied without TZ. If this passes, timestamps or sudoers loading are wrong."
    )
    assert _sudo_as(client, username, command, tz="XXX24") != 0, (
        f"CVE-2026-96512: TZ=XXX24 must not make expired NOTAFTER={notafter} allow "
        f"{command} for {username!r}. Unfixed sudo treats the stamp via mktime() under TZ."
    )

    notbefore = _local_gentime(datetime.now() + timedelta(hours=2))
    sudoers = f"{username} ALL=(ALL) NOTBEFORE={notbefore} NOPASSWD: {command}\n"
    client.fs.write(drop_in, sudoers)
    visudo = client.host.conn.run(f"visudo -cf {drop_in}")
    assert visudo.rc == 0, f"visudo rejected {drop_in}: stderr={visudo.stderr!r} stdout={visudo.stdout!r}"

    assert _sudo_as(client, username, command) != 0, (
        f"Sanity: NOTBEFORE={notbefore} is ~2h ahead; sudo -n {command} as {username!r} must be denied without TZ."
    )
    assert _sudo_as(client, username, command, tz="XXX-24") != 0, (
        f"CVE-2026-96512: TZ=XXX-24 must not make future NOTBEFORE={notbefore} allow "
        f"{command} for {username!r}. Unfixed sudo treats the stamp via mktime() under TZ."
    )
