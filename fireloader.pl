#!/usr/bin/perl -T
# -----------------------------------------------------------------------------
# Fireloader
# Iptables firewall management script
#  - Created by toby@oxborrow.net
#
# If you are looking for the filewall rules, see: /etc/firewall.conf
#
# Version 1.0   - 20081204 Initial version
#         1.1   - 20081223 Added output-accept mode, removed restart
#         2.0   - 20090430 Perl rewrite, changed backup checks
#         2.1   - 20090812 Add lockfile support
# -----------------------------------------------------------------------------
#
#
# -- HOW TO RUN AT STARTUP ----------------------------------------------------
# chmod +x fireloader.pl
# mv fireloader.pl /usr/local/bin 
# mv fireloader.conf /etc
#
# RedHat:   
#           Symlink this file in /etc/init.d/fireloader
#           chkconfig --add fireloader
# Debian:   
#           create the file /etc/network/if-up.d/fireloader as follows:
#           
#             #!/bin/bash
#             set -e
#             if [ "$IFACE" != "eth0" ]; then
#               exit 0
#             fi
#             if [ "$MODE" != "start" ]; then
#               exit 0
#             fi
#             /usr/local/bin/fireloader.pl start
#
#           chmod +x /etc/network/if-up.d/fireloader
#
# The following comments are required by redhat's chkconfig
# DO NOT REMOVE
#
# chkconfig: 2345 08 92
# description:  Manage the iptables firewall
#
# -----------------------------------------------------------------------------
#
use strict;
use warnings;
$ENV{PATH} = '';

use Data::Dumper;
use Date::Pcalc qw(:all);    # deb: libdate-pcalc-perl
use Digest::MD5;             # deb: libdigest-md5-file-perl
use File::Spec;
use File::Path;
use File::Copy qw(copy move);

# Get the date and time and put them together for unique backup names
my $DATE = sprintf( '%04u%02u%02u.%02u%02u%02u', Today_and_Now() );

my $LOCKFILE = '/var/run/fireloader.lock';

# Important files and directories
my $RULES_FILE           = '/etc/fireloader.conf';
my $STOP_RULES_FILE      = '/etc/fireloader-down.conf';
my $BACKUP_DIR           = '/root/fireloader-backups';
my $BACKUP_IPTABLES_FILE = File::Spec->catfile( $BACKUP_DIR, "iptables.save.$DATE" );
my $BACKUP_RULES_FILE    = File::Spec->catfile( $BACKUP_DIR, "fireloader.conf.$DATE" );
my $LAST_IPTABLES_FILE   = File::Spec->catfile( $BACKUP_DIR, 'iptables.save.last' );
my $LAST_RULES_FILE      = File::Spec->catfile( $BACKUP_DIR, 'fireloader.conf.last' );

# Required Kernel modules to load
# As of kernel 2.6.19 some module names changed, eg... ip_nat_ftp is now nf_nat_ftp
my @MODULES = qw(ip_tables iptable_nat nf_conntrack nf_conntrack_ftp nf_nat_ftp ip_queue);

exit main();


sub main
{
    checkRequiredFile($RULES_FILE);
    checkRequiredDir( $BACKUP_DIR, 1, 1 );
    checkRequiredProgram('/sbin/modprobe');
    checkRequiredProgram('/sbin/iptables-save');
    checkRequiredProgram('/sbin/iptables-restore');
    checkRequiredProgram('/bin/mktemp');
    checkRequiredProgram('/bin/gzip');

    if (-f $LOCKFILE) { die "Fireloader can not start, lockfile found\n"; }

    open(LOCK,">$LOCKFILE") || die "Fireloader can not start, lockfile error\n";
    close(LOCK);

    my $COMMAND = lc( $ARGV[0] );

    if ( $COMMAND eq 'start' ) {
            start();
    } elsif ( $COMMAND eq 'stop' ) {
            stop();
    } elsif ( $COMMAND eq 'restart' ) {
            start();
    } elsif ( $COMMAND eq 'backup' ) {
            saveBackup();
    } else {
            print "Usage: $0 (start|stop|restart|backup)\n";
    }

    unlink($LOCKFILE);
    return 0;
}

sub start
{
    loadModules();
    saveBackup();
    loadRules();
}

sub loadRules
{
    print "Starting the firewall: ";
    my $ec = restoreRules($RULES_FILE);
    if ( $ec > 0 ) {
        print "Error loading rules!\n";
        print "Loading last known working state: ";
        $ec = restoreRules($LAST_IPTABLES_FILE);
        if ( $ec > 0 ) {
            print "Error\n";
            print "Sorry, you are on your own\n";
        } else {
            print "OK\n";
            print "Your rules were not loaded\n";
        }
        exit 1;
    } else {
        print "OK\n";
        exit 0;
    }
}

sub stop
{
    saveBackup();

    print "Shutting down the firewall... ";
    my $ec = restoreRules($STOP_RULES_FILE);
    if ( $ec > 0 ) {
        print "Error loading stop rules!\n";
        # just do what we *think* the stop rules file would do
        print "Time for Plan B... ";
        $ec = 0;
        system("/sbin/iptables -F");
        $ec += $?;
        system("/sbin/iptables -X");
        $ec += $?;
        system("/sbin/iptables -F -t nat");
        $ec += $?;
        system("/sbin/iptables -X -t nat");
        $ec += $?;
        system("/sbin/iptables -F -t mangle");
        $ec += $?;
        system("/sbin/iptables -X -t mangle");
        $ec += $?;

        if ($ec) {
            print "Error\n";
            print "Sorry, you are on your own\n";
            exit 1;
        }
        print "OK\n";
    } else {
        print "OK\n";
    }
}

sub restoreRules($)
{
    my $rulesFile = shift || return 1;

    if ( !-f $rulesFile ) { return 1; }
    if ( !-s $rulesFile ) { return 1; }
    if ( !-r $rulesFile ) { return 1; }

    open( RULES, $rulesFile ) || return 1;
    my @rules = <RULES>;
    close(RULES);

    open( IPTABLES, '|/sbin/iptables-restore' ) || return 1;
    print IPTABLES @rules;
    close(IPTABLES);

    return $?;
}

sub loadModules
{
    print 'Loading modules: ';
    foreach my $module (@MODULES) {
        system("/sbin/modprobe $module");
        if ( $? > 0 ) {
            unlink $LOCKFILE;
            die "Error loading module '$module', will not continue";
        }
    }
    print "OK\n";
}

sub saveBackup
{
    print "Saving backups to $BACKUP_DIR... ";
    my $changes = 0;

    # compare the current and last iptables-save output
    my $currentLoadedRulesFile = saveLoadedIptablesRules();
    if ( !$currentLoadedRulesFile ) {
        unlink $LOCKFILE;
        die "Error: Could not save iptables-save output to temporary file\n";
    }

    my ( $lastSize, $lastMD5, $currentSize, $currentMD5 );

    # backup the output of iptables-save
    $lastSize    = ( -s $LAST_IPTABLES_FILE ) || 0;
    $lastMD5     = getFileMD5($LAST_IPTABLES_FILE);
    $currentSize = ( -s $currentLoadedRulesFile ) || 0;
    $currentMD5  = getFileMD5($currentLoadedRulesFile);

    if ( ( $currentSize == $lastSize ) && ( $currentMD5 eq $lastMD5 ) ) {
        unlink $currentLoadedRulesFile;
    } else {
        $changes++;
        move $currentLoadedRulesFile, $BACKUP_IPTABLES_FILE;
        copy $BACKUP_IPTABLES_FILE,   $LAST_IPTABLES_FILE;
        system("/bin/gzip $BACKUP_IPTABLES_FILE");
    }

    # backup the user rules file
    $lastSize    = ( -s $LAST_RULES_FILE ) || 0;
    $lastMD5     = getFileMD5($LAST_RULES_FILE);
    $currentSize = -s $RULES_FILE;
    $currentMD5  = getFileMD5($RULES_FILE);

    if ( ( $currentSize == $lastSize ) && ( $currentMD5 eq $lastMD5 ) ) {
        # nothing
    } else {
        $changes++;
        copy $RULES_FILE,        $BACKUP_RULES_FILE;
        copy $BACKUP_RULES_FILE, $LAST_RULES_FILE;
        system("/bin/gzip $BACKUP_RULES_FILE");
    }

    if ($changes) {
        print "OK\n";
        return 1;
    } else {
        print "no change\n";
        return 0;
    }
}

sub saveLoadedIptablesRules
{
    my $filename = '';

    open( MKTEMP, '/bin/mktemp|' ) || return '';
    $filename = <MKTEMP>;
    close(MKTEMP);

    if ( !$filename ) { return ''; }
    $filename =~ m/^(.*)$/;
    $filename = $1;

    open( IPTABLES, '/sbin/iptables-save|' ) || return '';
    my @rules = <IPTABLES>;
    close(IPTABLES);

    # remove the non-important variable fluff
    @rules = grep( !/^#/,       @rules );
    @rules = grep( !/^\s*$/,    @rules );
    @rules = grep( !/fail2ban/, @rules );

    # reset the counters to 0
    foreach my $rule (@rules) {
        $rule =~ s/^:([A-Z\s]+).*/:$1 [0:0]/;
    }

    open( FILE, ">$filename" ) || return '';
    print FILE @rules;
    close(FILE);

    return $filename;
}

sub getFileMD5($)
{
    my $filename = shift;

    my $md5 = '';

    if ( !$filename ) { warn "Warning: No file passed to getFileMD5\n"; return $md5; }
    if ( !-f $filename ) { return $md5; }

    open( FILE, $filename ) || return $md5;
    binmode(FILE);
    $md5 = Digest::MD5->new->addfile(*FILE)->hexdigest;
    close(FILE);

    return $md5;
}

sub checkRequiredDir
{
    my $directory = shift;
    my $create    = shift || 0;
    my $writable  = shift || 0;

    if ( !-d $directory ) {
        if ($create) {
            warn "Warning: Required directory '$directory' was not found, creating...\n";
            if ( !mkpath($directory) ) {
                die "Error: Could not create directory\n";
            }
        } else {
            die "Error: Required directory '$directory' was not found\n";
        }
    }

    if ($writable) {
        if ( !-w $directory ) {
            die "Error: Required directory '$directory' is not writable\n";
        }
    }
}

sub checkRequiredFile
{
    my $file = shift;
    my $writable = shift || 0;

    if ( !-f $file ) {
        die "Error: Required file '$file' was not found\n";
    }

    if ($writable) {
        if ( !-w $file ) {
            die "Error: Required file '$file' is not writable\n";
        }
    }
}

sub checkRequiredProgram
{
    my $program = shift;

    if ( !-f $program ) {
        die "Error: Required program '$program' was not found\n";
    }

    if ( !-e $program ) {
        die "Error: Required program '$program' is not executable by this user\n";
    }
}

