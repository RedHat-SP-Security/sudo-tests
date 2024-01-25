#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/sudo/Sanity/io-logging
#   Description: Test tries several sudoers options stored in ldap. It tries both ways howto get them - native sudo-ldap and sssd.
#   Author: David Spurek <dspurek@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2014 Red Hat, Inc.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include Beaker environment
. /usr/bin/rhts-environment.sh || :
. /usr/share/beakerlib/beakerlib.sh || exit 1


rlJournalStart && {
    rlPhaseStartSetup && {
        rlRun "rlImport --all" || rlDie 'cannot continue'
        # Check reqiured packages.
        rlRun "rlCheckMakefileRequires" || rlDie "cannot continue"

        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        CleanupRegister "rlRun 'rm -r $TmpDir' 0 'Removing tmp directory'"
        CleanupRegister 'rlRun "popd"'
        rlRun "pushd $TmpDir"
        CleanupRegister 'rlRun "rsyslogCleanup"'
        rlRun "rsyslogSetup"
        CleanupRegister 'rlRun "sudoCleanup"'
        rlRun "sudoSetup"
        CleanupRegister 'rlRun "rlFileRestore"'
        rlRun "rlFileBackup --clean /var/log/sudo.log /var/log/sudo-io/ /etc/nslcd.conf"

        rm -f /var/log/sudo.log
        rm -rf /var/log/sudo-io

        CleanupRegister 'rlRun "testUserCleanup"'
        rlRun "testUserSetup"

        rlRun "sudoSwitchProvider files"
        rlRun "cat /etc/nsswitch.conf"
        rlRun "sudoAddSudoRule --nowait 'defaults'"
        exclam='!'
        rlRun "sudoAddOptionToSudoRule --nowait 'defaults' 'sudoOption' '${exclam}authenticate'"
        rlRun "sudoAddOptionToSudoRule --nowait 'defaults' 'sudoOption' '${exclam}requiretty'"
        rlRun "sudoAddOptionToSudoRule --nowait 'defaults' 'sudoOption' 'log_output'"
        rlRun "sudoAddOptionToSudoRule --nowait 'defaults' 'sudoOption' 'log_input'"
        rlRun "sudoAddOptionToSudoRule --nowait 'defaults' 'sudoOption' 'iolog_dir=/var/log/sudo-io'"
        rlRun "sudoAddOptionToSudoRule --nowait 'defaults' 'sudoOption' 'logfile=/var/log/sudo.log'"
        rlRun "sudoAddOptionToSudoRule --nowait 'defaults' 'sudoOption' 'syslog=authpriv'"

        rlRun "sudoAddSudoRule --nowait 'rule_allow'"
        rlRun "sudoAddOptionToSudoRule --nowait 'rule_allow' 'sudoHost' 'ALL'"
        rlRun "sudoAddOptionToSudoRule --nowait 'rule_allow' 'sudoUser' '$testUser'"
        rlRun "sudoAddOptionToSudoRule --nowait 'rule_allow' 'sudoCommand' 'ALL'"
        rlRun "cat /etc/sudoers"
        rsyslogResetLogFilePointer /var/log/secure
    rlPhaseEnd; }

    rlPhaseStartTest 'sudo format' && {
        rm -f /var/log/sudo.log
        rlRun "su - $testUser -c 'cp /bin/ls \"./my ls\"'" 0
        rlRun "su - $testUser -c 'sudo \"./my ls\"'" 0
        sleep 3
        rlRun -s "rsyslogCatLogFileFromPointer /var/log/secure"
        rlAssertGrep 'my#040ls' $rlRun_LOG
        rlRun -s "cat /var/log/sudo.log"
        rlAssertGrep 'my#040ls' $rlRun_LOG
        rlRun -s "sudoreplay -l"
        rlAssertGrep 'my#040ls' $rlRun_LOG
    rlPhaseEnd; }

    rlPhaseStartTest 'json format' && {
        rlRun "sudoAddOptionToSudoRule --nowait 'defaults' 'sudoOption' 'log_format=json'"
        rm -f /var/log/sudo.log
        rlRun "su - $testUser -c 'cp /bin/ls \"./my ls\"'" 0
        rlRun "su - $testUser -c 'sudo \"./my ls\"'" 0
        sleep 3
        rlRun -s "cat /var/log/sudo.log"
        rlAssertGrep 'my ls' $rlRun_LOG
        rlRun -s "sudoreplay -l"
        rlAssertGrep 'my#040ls' $rlRun_LOG
    rlPhaseEnd; }

    rlPhaseStartCleanup && {
        CleanupDo
    rlPhaseEnd; }
  rlJournalPrintText
rlJournalEnd; }
