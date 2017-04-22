#!/usr/bin/perl
#
# "unreal-fingerprint.pl" - SSL Certificate SHA256 fingerprint validation & substitution program
#
# M. Cockrem - michael.cockrem@au.fujitsu.com
#
# 28/02/2017 v0.1a	Initial release
# 01/03/2017 v0.5a	Error handling for edge cases
# 02/03/2017 v0.6	Bug squashing, various refactoring
# 03/03/2017 v1.0	Fixed watchdog code. Cleanup.
# 03/06/2017 v1.1   Fingerprint regex bug squash
#
# About: This program reads input from $HashFile, expecting a SHA256 hashed fingerprint
# 'a\n' followed by a second fingerprint 'b\n'. If these are found in a plaintext
# file, the program validates them & either exits if they do not match the expected
# fingerprint syntax or continues & finds $TargetFile, searches for fingerprint 'a'
# in that file & replaces it with the 'b' fingerprint before commiting a syscall to
# rehash configuration file '$TargetFile'.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;
use warnings FATAL => 'all';
use POSIX qw(strftime);
use File::Copy;

my $hName;
my @inarray;          # hold wanted hashfile contents
my $Target   = "0";   # Track if expected old fingerprint found
my $fLineCnt = "0";   # Track hashfile linecount
my $FH0; my $FH1; my $FH2; my $FH3; 
my $DateTime = strftime "%F",          localtime;
my $LogTime  = strftime "%F %H:%M:%S", localtime;
# -----------------------------------------------------------
# User Variables - change to the appropriate file paths here:
# -----------------------------------------------------------
my $verbosity  = "1";                                         # Logging level: 0 off (default) | 1 Informational | 2 extended | 3 Debugging (noisy)
my $WorkPath   = "/srv/irc";                                  # Set your unrealircd directory path here
my $LogFile    = "$WorkPath/logs/$0.log";                     # Log file name and location
my $HashFile   = "/home/mike/hashfile.out";                 # Hash file name and location the external server dumps file to
my $TargetF    = "$WorkPath/conf/unrealircd.conf";            # Unmodified target configuration file "n"
my $BackupF    = "$WorkPath/conf/unrealircd.conf.$DateTime";  # Filename target to move $OriginalF "n"
my $RehashCmd  = "$WorkPath/unrealircd rehash";               # Path and command to rehash configuration file
my $Configured = "0";                                         # Change this to "1" once you've configured the above
# -----------------------------------------------------------

#################
#  Main module  #
#################

open STDOUT, '>>', $LogFile || die "Test"; # Log redirection
open STDERR, '>&', STDOUT;
 &LogInfo();
 &Preflight();
 &GetData();
 &Validation();
 &MoveFile();
 &ReplaceData();
 &Rehash();
 &Cleanup();
close STDOUT;

#################
#  Subroutines  #
#################

################################################################################
## LogInfo subroutine
## additional runtime information to logging file
#################################################################################
sub LogInfo {
    chomp( $hName = `uname -n` );
    if ( $verbosity ge "1" ) { print "$LogTime $0 execution on $hName, any errors will be recorded below, depending on logging level:\n"; }
}

################################################################################
## Preflight subroutine
## Function:
## Check file existance and permissions. Check end user configuration completed
#################################################################################
sub Preflight {
    if ( $Configured == 0 ) { die "Error: It looks like you haven't configured this script, please check the FILE PATH variables and -hint- the configuration flag. Terminating\n\a"; }
    if ( -e $BackupF ) { die "Error: Backup file ($BackupF) already exists with this timestamp (Did you mean to run this twice?): Terminating.\n\a"; }
    if ( ( !-T $TargetF ) || ( !-w $TargetF ) ) { die "Error: $TargetF is not found, garbage or not writable: Terminating.\n\a"; }
    if ( ( !-T $HashFile ) || ( !-r $HashFile ) ) { die "Error: $HashFile is not found, garbage or not readable: Terminating.\n\a"; }
    
    if ( ! -e $HashFile ) 
    { 
        if ( $verbosity ge "1" ) { print "We ran but there was no hashfile to be found ($HashFile) so we exited normally, probably not time for renewal yet.\n"; }
        exit (0); 
    }
}	

###############################################################################
## GetData subroutine
## Function:
## Read in hash file for verification by 'Verify' subroutine
################################################################################
sub GetData {
    open( $FH0, $HashFile ) || die "Error: File $HashFile not found or file handle error, Terminating.\n\a";
    while (<$FH0>) {
        chomp;
        push @inarray, $_;
        $fLineCnt++;
	if ( $verbosity == "3" ) { print "Debug: $_, line count: $fLineCnt\n"; }
    }
    close($FH0) || print "WARN: File handle closure error: $FH0";
    
    open( $FH1, $TargetF ) || die "Error: File $TargetF not found or file handle error, Terminating.\n\a";
    while (<$FH1>) {
        chomp;
        if ( $verbosity == "3" ) { print "Debug: Target Count: $Target, buffer content: $_\n"; }
	if ( $_ =~ /password "$inarray[0]";/ ) { $Target++; }
    }
    close($FH1) || print "WARN: File handle closure error: $FH1";
}

###############################################################################
## Validation subroutine
## Function:
## Ensure hash input is exactly 2 lines and a valid SHA256 fingerprint format
################################################################################
sub Validation {
    if ( $fLineCnt != 2 ) 
    { 
        die "Error: Unexpected length in $HashFile: ($fLineCnt), Terminating.\n\a";
    }

    if (( $inarray[0] !~ /^([A-Z0-9]{2}:){31}[A-Z0-9]{2}$/i ) || ( $inarray[1] !~ /^([A-Z0-9]{2}:){31}[A-Z0-9]{2}$/i ))
    {
        die "Error: Incorrect hash format in $HashFile, Terminating.\n\a";
    }
    if ( $Target == 0 ) 
    { 
        if ( $verbosity ge "2" ) { print "The old SHA256 fingerprint wasn't found in $TargetF, nothing to do. Exiting normally.\n"; }
        if ( $verbosity == "3" ) 
        { 
            print "Note: This is normal if the configuration is up to date. However, if you see this message\n", 
            "but the fingerprint isn't correct it means what the sending host believes is the correct\n",
            "old fingerprint doesn't match what you last recorded as a valid fingerprint\n",
	    "Recommend you contact the sysadmin of the sending host.\n";
	}
        exit ( 0 );
    }
}

###############################################################################
## MoveFile subroutine
## Function:
## Move existing configuration file to a backup appended by today's date
## prerequisite for ReplaceData subroutine
################################################################################
sub MoveFile {
    move( $TargetF, $BackupF ) || die "Fatal error moving file $TargetF to $BackupF (Permissions?): Terminating.\n\a";
    if ( $verbosity ge "2" ) { print "Moved $TargetF to $BackupF\n"; }
}

###############################################################################
## ReplaceData subroutine
## Function:
## Open backup file and touch+write to configuration file, substitute old
## has for new hash held in @inarray. This might seem like a poor way to do it
## but ALL inline calls to sed/perl/awk/&ct do this in the background actually..
################################################################################
sub ReplaceData {
    $SIG{ALRM} = sub { watchdoggo() };
    alarm(180);
    eval {
        open( $FH2, "<$BackupF" ) || die "Error: File $BackupF not found or file handle error, Terminating\n\a";
        open( $FH3, ">$TargetF" ) || die "Error: File $TargetF not found or file handle error, Terminating\n\a";
        while (<$FH2>) {
            $_ =~ s/password "$inarray[0]";/password "$inarray[1]";/g;
            print $FH3 $_;
            if ( $verbosity == "3" ) { print "Debug: $_\n"; }
	}
        close($FH2) || print "WARN: File handle closure error: $FH2";
        close($FH3) || print "WARN: File handle closure error: $FH3";
        alarm(0);
    };
}

###############################################################################
## Rehash subroutine
## Function:
## Make a POSIX system call as defined by $RehashCmd
################################################################################
sub Rehash {
    $SIG{ALRM} = sub { watchdoggo() };
    alarm(180);
    eval {
	if ( $verbosity ge "2" ) { print "Rehashing...\n"; }
        system("$RehashCmd");
        alarm(0);
    };
}

###############################################################################
## Rehash subroutine
## Function:
## We are finished with the hash file, all being well (we should have trapped
## any errors before now "(OwO)) so go ahead and remove that file so we aren't
## triggered again without reason.
#################################################################################
sub Cleanup {
	if ( $verbosity ge "2" ) { print "Removing $HashFile\n"; }
	unlink $HashFile ||  die "Error: Could not remove $HashFile, Please remove manually! Terminating\n\a";
}

###############################################################################
## watchdog subroutine
## Function:
## Not normally used. Just called to write to log and die if the MAIN timer
## expires, indicating the task hung for some reason or other. Note: The
## watchdoggo is actually just a big ol' watchpupper....
################################################################################
sub watchdoggo {
    die "Fatal error! watchdog timer expired: Terminating.\n\a";
