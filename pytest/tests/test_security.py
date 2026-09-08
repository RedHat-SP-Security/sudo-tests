"""
SUDO Security CVE Tests.

:requirement: sudo
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology

_CVE_82474_EXECVEAT_SRC = Path(__file__).resolve().parent.parent / "data" / "cve_82474_execveat.c"
_CVE_82474_HELPER_BIN = "/tmp/cve_82474_execveat"
_CVE_82474_SUDOERS = "/etc/sudoers.d/00-cve-82474-intercept"

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


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.BareClient)
def test_cve__execveat_intercept_policy_bypass(client: Client):
    """
    :title: CVE-2026-82474: ptrace intercept must policy-check execveat(2)
    :setup:
        1. Require sudo with intercept support and seccomp trap (intercept_type=trace)
        2. Create local user "testuser"
        3. Install a helper that runs /usr/bin/id via execveat(2)
        4. Add sudoers drop-in with Defaults intercept, intercept_type=trace, and a rule
           allowing only the helper in INTERCEPT mode
        5. Enable local SSSD + sudo
    :steps:
        1. Run the helper via sudo as testuser
    :expectedresults:
        1. execveat of the denied /usr/bin/id is rejected (helper exits non-zero)
    :customerscenario: False
    """
    if client.host.compare_package_version({"major": 1, "minor": 9, "patch": 8}, "sudo") < 0:
        pytest.skip("sudo intercept support requires sudo >= 1.9.8")

    seccomp_trap = client.host.conn.run("grep -qw trap /proc/sys/kernel/seccomp/actions_avail 2>/dev/null")
    if seccomp_trap.rc != 0:
        pytest.skip("seccomp trap action unavailable; intercept_type=trace is not supported on this host")

    username = "testuser"
    helper_src = _CVE_82474_EXECVEAT_SRC.read_text(encoding="utf-8")
    helper_src_path = f"{_CVE_82474_HELPER_BIN}.c"

    client.user(username).add(uid=10001, password="Secret123")
    client.host.conn.run("dnf install -y gcc", raise_on_error=False)

    client.fs.write(helper_src_path, helper_src)
    compile_helper = client.host.conn.run(f"gcc -o {_CVE_82474_HELPER_BIN} {helper_src_path}")
    assert compile_helper.rc == 0, (
        f"Failed to compile execveat helper for CVE-2026-82474: rc={compile_helper.rc} "
        f"stderr={compile_helper.stderr!r} stdout={compile_helper.stdout!r}"
    )
    client.fs.chmod(path=_CVE_82474_HELPER_BIN, mode="ugo+rx")

    sudoers = (
        "Defaults intercept\n"
        "Defaults intercept_type=trace\n"
        f"{username} ALL=(ALL) NOPASSWD: INTERCEPT: {_CVE_82474_HELPER_BIN}\n"
    )
    client.fs.write(_CVE_82474_SUDOERS, sudoers)
    client.fs.chmod(path=_CVE_82474_SUDOERS, mode="ugo+r")
    visudo = client.host.conn.run(f"visudo -cf {_CVE_82474_SUDOERS}")
    assert visudo.rc == 0, (
        f"visudo rejected {_CVE_82474_SUDOERS}: sudoers syntax is invalid so sudo would not load the "
        f"CVE intercept test fragment. stderr={visudo.stderr!r} stdout={visudo.stdout!r}"
    )

    client.sssd.common.local()
    client.sssd.common.sudo()
    client.sssd.start()

    result = client.auth.sudo.run_advanced(username, "Secret123", command=_CVE_82474_HELPER_BIN)
    assert result.rc != 0, (
        "CVE-2026-82474: intercept mode must deny execveat of /usr/bin/id from the allowed helper; "
        f"got rc={result.rc} stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "uid=0" not in result.stdout, (
        "CVE-2026-82474: helper must not run /usr/bin/id as root via execveat bypass; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
