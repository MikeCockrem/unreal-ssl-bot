#!/usr/bin/perl
# -------------------------------------------------------------------------------------------------
=pod

=head1 LetsEncrypt wrapper program ("LetsEnscript.pl")

 M. Cockrem - mikecockrem@gmail.com

 23/03/2017  v0.3a      Initial release
 20/04/2017  v0.4a      Debugging, added expiry checks.
 22/04/2017  v0.4.1a    Layout and formatting standardisation
 01/05/2017  v1.0b	Karoshi desma version

=head2 About:

        This script is designed to automate (via cron of course) renewal of LetsEncrypt(TM) certificates (validated by DNS) used in conjunction with 
	UnrealIRC(TM) ircd daemon. It is also designed to push the SSL fingerprint to a leaf node in the Unreal IRC network so that the sister script
	can grab the new fingerprint on the leaf node (https://github.com/MikeCockrem/unreal-ssl-bot/blob/master/unreal-fingerprint.pl)

	As shown in "order of execution" (below) this script will check if we are within the renewal window and if so will take a backup of the existing certificate,
	call le.pl to renew, append the	CA's root certificate (as required by Unreal), push a copy of the ssl fingerprint to the leaf node and rehash the unreal daemon.

	 NB:	The initial DNS verification should be run manually (i.e. not by this script) for the first time in order to get the DNS challenge set up, I
		don't know why but le.pl WONT show that output when run via `qx` this is a limitation of the LetsEncrypt provided scripts/libs.
		Don't forget to set up the private/public key pair and ssh config file as required.

=head2 Order of execution:

START
 \
 |   GetChecks          Check if we're running as a user who can perform the necessary functions/access relevant files
 |   CheckExpiry        Checks expiry date of SSL certificate and quits script early if renewal is not required.
 |   BackupCrt		Backup existing certificate
 |   LetsEnc            Use the le.pl/Crypt::LE (ver. >21) to query for/request renewal [ quit here if unable to renew ]
 |     \
 |      | AppendRC      If LetsEncrypt le.pl has provided new cert, append LE's root certificate to end (unreal needs full chain)
 |      | GetHash       Extract OLD hash from expired cert and new hash from new hash and write to file
 |      \ PushRemote    SCP the hash file from GetHash subroutine and send to leaf node (do this early before reload)
 |
 |   FixPerms           Fixup the new certificate ownership/permissions
 |   Rehash             System call to restart unreal; This should complete the operation.
 \
 END

=head2 Dependencies:

 - Perl (5.x)
 - Net::SCP
 - Crypt::LE / le.pl (**VERSION >=20 prerequisite**)
 - File::Copy
 - Net::SSL::ExpireDate
 - Unreal IRC daemon

=head2 Bugs/Limitations:

 - Currently limited to only one leaf node for notification
 - Initial DNS verification when calling le.pl must be run by hand the first time
 - Probably would fail in a lot of edge-cases.	
 - Net::SCP requires key authentication that's ".ssh/id_rsa" by default
   you could always edit the .ssh/config file though...

=head2 Licence:

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

=cut
# -------------------------------------------------------------------------------------------------

use strict;
use warnings FATAL => 'all';
use POSIX qw(strftime);
use Net::SSL::ExpireDate;
use File::Copy;
use Net::SCP;

# -----------------------------------------------------------
# User Variables - change to the appropriate file paths here:
# -----------------------------------------------------------
my $verbosity		= "2";					   # Logging level: 0 off (default) | 1 Informational | 2 extended | 3 Debugging (noisy)
my $RemoteServer 	= "203.59.73.131";                  	   # Address of remote server to notify (SCP)
my $RemoteUser   	= "mike";                          	   # Remote server username (SCP)
my $DestLoc		= "/home/mike";				   # Destination path on remote server for hashfile, without trailing slash (SCP)
my $RootCert 		= "lets-encrypt-x3-cross-signed.pem.txt";  # Name of LE's chain file (in $WorkPath) https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem.txt
my $WorkPath 		= "/srv/irc/conf/ssl";                     # Location path (No trailing slash)
my $LogFile    		= "$WorkPath/$0.log";                      # Log file name and location
my $CertName 		= "irc.afk47.org.pem";                     # Certificate name
my $UID 		= 0;                                       # UID for certificate (500 = he113294)
my $GID 		= 501;                                     # GID for certificate (10 = wheel)
my $PERMS 		= 0640;                                    # File permissions for certificate (-rw-------)
my $HashFile 		= "HashFile.out";                          # SSL Fingerprints file
my $Domains 		= "irc.afk47.org";                         # Target domain name
my $CSRKey 		= "le-irc.afk47.org.signing.key";          # Certificate Signing Request private key (LE Private key)
my $CSRFile 		= "le-irc.afk47.org.csr";                  # Certificate Signing Request file (CSR)
my $PriKey 		= "irc.afk47.org.key";                     # Certificate/Domain private key
my $ExpiryDeadline 	= "7 days";      			   # How long should we wait to renew? (Don't forget to change --renew (n) in the LetsEnc module)
my $Configured		= "1";					   # Change this to "1" once you've configured the above
#
# ----- No need to change anything below this line ----
#
my $FH0;
my $FH1;
my $FH2;
my $expire_date;
my $ExpiryCheck;
my $ExpireDate;
my $Expired;
my $NowTime = strftime "%F", localtime;

#################
#  Main module  #
#################

open STDOUT, '>>', $LogFile;
open STDERR, '>&', STDOUT;
 print "$0 execution: $NowTime\n";
 &GetChecks();
 &CheckExpiry();
 &BackupCrt();
 &LetsEnc();
 &FixPerms();
 &Rehash();
close STDOUT;

#################
#  Subroutines  #
#################

sub GetChecks {
    if ( $Configured == 0 ) { die "Error: It looks like you haven't configured this script, please check the FILE PATH variables and -hint- the configuration flag. Terminating\n\a"; }
    if ( ( !-T $LogFile ) || ( !-w $LogFile ) ) { die "Error: $LogFile not writable or bad path: Terminating.\n\a"; }
    my $UIDname = POSIX::cuserid();
    if ( $UIDname ne "root" ) { die "WARN: Script MUST be run with root privileges\n"; }
}

sub CheckExpiry {
    $ExpiryCheck = Net::SSL::ExpireDate->new( file  => "$WorkPath/$CertName" );
    if (defined $ExpiryCheck->expire_date) {
        $ExpireDate = $ExpiryCheck->expire_date;
        $Expired = $ExpiryCheck->is_expired($ExpiryDeadline);
        if (not defined $Expired) { die "$CertName Not expired: ($ExpireDate)\n"; } # Leave script
    } else {
            die "FATAL: Could not establish certificate expiry dates for $WorkPath/$CertName\n";
    }
}

sub BackupCrt {
    if ( -e "$WorkPath/$CertName.$NowTime" ) { die "Error: Backup file ($WorkPath/$CertName.$NowTime) already exists with this timestamp (Did you mean to run this twice?): Terminating.\n\a"; }
    copy( "$WorkPath/$CertName","$WorkPath/$CertName.$NowTime" ) || die "Fatal error backing up $CertName\n";
    if ( $verbosity ge "2" ) { print "Copied $WorkPath/$CertName to $WorkPath/$CertName.$NowTime\n"; }
}

sub LetsEnc {
    $SIG{ALRM} = sub { watchdoggo() };
    alarm(180);
    eval {
        if (qx{which le.pl 2>&1>/dev/null}, $? != 0 ) { die "FATAL: le.pl Not found, can't continue! ($?)\n"; }
        my @argsarray = (
                "--key $WorkPath/$CSRKey",
                "--csr $WorkPath/$CSRFile",
                "--csr-key $WorkPath/$PriKey",
                "--crt $WorkPath/$CertName",
                "--domains $Domains",
                "--handle-with Crypt::LE::Challenge::Simple",
                "--handle-as dns",
                "--renew 7",
                "--live",
                "--issue-code=88",
        );
        my $args = join ' ', @argsarray;

        if ( $verbosity ge "2" ) { print "Called le.pl: /usr/local/bin/le.pl $args\n"; }
        qx(/usr/local/bin/le.pl $args); # Perlception

        #Code 88 will be returned by le.pl if the renewal was successful
        if ( $? eq 88) {
                &AppendRC();
                &GetHash();
                &PushRemote();
        } else {
                die "FATAL: We were within renewal window but le.pl didn't return succesful renewal code: Exiting with failurei ($?)\n";
        }
        alarm(0);
    };

}

sub AppendRC {
    open ( FH0, ">>", "$WorkPath/$CertName" ) || die "Couldn't open $WorkPath/$CertName\n";
    open ( FH1, "<", "$WorkPath/$RootCert" ) || die "Couldn't open $WorkPath/$RootCert\n";
    while ( my $readline = <FH1> ) { 
        print FH0 $readline;
    }
    close ( FH0 ) || die "Error closing file handle FH0\n";
    close ( FH1 ) || die "Error closing file handle FH1\n";
}

sub GetHash {
    my $OldFingerprint = qx(openssl x509 -sha256 -fingerprint -noout -in $WorkPath/$CertName.$NowTime | cut -d = -f2 | tr -d '\n') || die "Couldn't evaluate $WorkPath/$CertName.$NowTime fingerprint, aborting!\n";
    my $NewFingerprint = qx(openssl x509 -sha256 -fingerprint -noout -in $WorkPath/$CertName | cut -d = -f2 | tr -d '\n')|| die "Couldn't evaluate $WorkPath/$CertName fingerprint, aborting!\n";
    open ( FH2, ">", "$WorkPath/$HashFile" ) || die "Couldn't create/open $WorkPath/$HashFile for writing\n";
    print FH2 "$OldFingerprint\n$NewFingerprint";
    close ( FH2 ) || die "Error closing file handle FH2\n";
}

sub PushRemote {
    $SIG{ALRM} = sub { watchdoggo() };
    alarm(180);
    eval {
        if ( ( !-T "$WorkPath/$HashFile" ) || ( !-r "$WorkPath/$HashFile" ) ) { die "Error: $WorkPath/$HashFile is not found, garbage or not readable: Terminating\n\a"; }
        my $scp = new Net::SCP( $RemoteServer, $RemoteUser );
        $scp->put( "$WorkPath/$HashFile" , "$DestLoc/$HashFile" ) || die "Test $scp->{errstr}";
        alarm(0);
    };
}

sub FixPerms {
    chmod $PERMS, "$WorkPath/$CertName" || die "Couldn't set permissions on $CertName\n";
    chown $UID, $GID, "$WorkPath/$CertName" || die "Couldn't set owner/group on $CertName\n";
    qx(restorecon "$WorkPath/$CertName"); # Can't use die here, best effort.
}

sub Rehash {
    system ( "service unreal stop" );
    sleep (2);
    system ( "service unreal start");
}

sub watchdoggo {
    die "Fatal error! watchdog timer expired: Terminating.\n\a";
}
