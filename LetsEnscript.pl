#!/usr/bin/perl
# -------------------------------------------------------------------------------------------------
=pod

=head1 LetsEncrypt wrapper program ("1.pl")

 M. Cockrem - mikecockrem@gmail.com
 23/03/2017  v0.3a      Initial release
 20/04/2017  v0.4a      Debugging, added expiry checks.
 22/04/2017  v0.4.1a    Layout and formatting standardisation

=head2 About:

        This program has horrible incomplete documentation. Good luck.
        TO DO: - Get all the filename variables straight and consistent

=head2 Dependencies:

        - Perl (5.x)
        - Net::SCP
        - Crypt::LE / le.pl (for call to le.pl) (VERSION >=20 prerequisite)
        - File::Copy
        - Net::SSL::ExpireDate
        - Unreal


=head2 Order of execution:

START
 \
 |   GetUID             Check if we're running as a user who can perform the necessary functions/access relevant files
 |   CheckExpiry        Checks expiry date of SSL certificate and quits script early if renewal is not required.
 |   LetsEnc            Use the le.pl/Crypt::LE (ver. >21) to query for/request renewal [ quit here if unable to renew ]
 |     \
 |      | AppendRC           If LetsEncrypt le.pl has provided new cert, append LE's root certificate to end (unreal needs full chain)
 |      | GetHash            Extract OLD hash from expired cert and new hash from new hash and write to file
 |      \ PushRemote         SCP the hash file from GetHash subroutine and send to leaf node (do this early before reload)
 |   InstallCert        Make a backup of the old file, then move the new certificate in place
 |   Rehash             System call to restart unreal; This should complete the operation.
 \
 END

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
use diagnostics;

use POSIX qw(strftime);
use Net::SSL::ExpireDate;
use File::Copy;
use Net::SCP;

# -----------------------------------------------------------
# User Variables - change to the appropriate file paths here:
# -----------------------------------------------------------
my $RemoteServer = "";                           # Address of remote server to notify (SCP)
my $RemoteUser   = "";                          # Remote server username (SCP)
my $RootCert = "lets-encrypt-x3-cross-signed.pem.txt";  # Name of LE's chain file (in $WorkPath) https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem.txt
my $WorkPath = "/srv/irc/conf/ssl";                     # Location path (No trailing slash)
my $CertName = ".crt";                     # Certificate name
my $CertNameTMP = ".crt.tmp";              # Temporary (new) certificate name
my $UID = 500;                                          # UID for certificate (500 = he113294)
my $GID = 10;                                           # GID for certificate (10 = wheel)
my $PERMS = 0600;                                       # File permissions for certificate (-rw-------)
my $HashFile = "HashFile.out";                          # SSL Fingerprints file
my $Domains = "";                          # Target domain name
my $CSRKey = "";            # Certificate Signing Request private key (LE Private key)
my $CSRFile = "";                  # Certificate Signing Request file (CSR)
my $PriKey = "";                   # Certificate/Domain private key
my $ExpiryDeadline = "1 day";      # How long should we wait to renew? (Don't forget to change --renew (n) in the LetsEnc module)
# - No need to change anything below this line -
my $FH0; my $FH1; my $FH2;
my $expire_date;
my $NowTime = strftime "%F-%H%M%S", localtime;
my $ExpiryCheck;
my $ExpireDate;
my $Expired;

#################
#  Main module  #
#################

&GetUID();
&CheckExpiry();
&LetEnc();
&InstallCert();
&Rehash();

#################
#  Subroutines  #
#################

sub GetHash {
    my $OldFingerprint = qx(openssl x509 -sha256 -fingerprint -noout -in $WorkPath/$CertName | cut -d = -f2 | tr -d '\n') || die "Couldn't evaluate $WorkPath/$CertName fingerprint, aborting!\n";
    my $NewFingerprint = qx(openssl x509 -sha256 -fingerprint -noout -in $WorkPath/$CertNameTMP | cut -d = -f2 | tr -d '\n')|| die "Couldn't evaluate $WorkPath/$CertNameTMP fingerprint, aborting!\n";
    open ( FH2, ">", "$WorkPath/$HashFile" ) || die "Couldn't create/open $WorkPath/$HashFile for writing\n";
    print FH2 "$OldFingerprint\n$NewFingerprint";
    close ( FH2 ) || die "Error closing file handle FH2\n";
}

sub InstallCert {
    copy( "$WorkPath/$CertName","$WorkPath/$CertName.$NowTime" ) || die "Fatal error backing up $CertName\n";
    move( "$WorkPath/$CertNameTMP","$WorkPath/$CertName" ) || die "Fatal error moving $CertName in to place\n";
    chmod $PERMS, "$WorkPath/$CertName" || die "Couldn't set permissions on $CertName\n";
    chown $UID, $GID, "$WorkPath/$CertName" || die "Couldn't set owner/group on $CertName\n";
    qx(restorecon "$WorkPath/$CertName"); # Can't use die here, best effort.
    unlink "$WorkPath/$CertNameTMP" || die "Couldn't clean up certificate temporary file in $WorkPath: $CertNameTMP\n";
}

sub CheckExpiry {
    $ExpiryCheck = Net::SSL::ExpireDate->new( file => '$WorkPath/$CertName' );

    if (defined $ExpiryCheck->ExpireDate) {
            $ExpireDate = $ExpiryCheck->ExpireDate;
            $Expired = $ExpiryCheck->is_expired($ExpiryDeadline);
            if (not defined $Expired) { die "Not expired\n"; } # Leave script
    } else {
            die "Could not establish certificate expiry dates\n";
    }
}

sub LetsEnc {
    if ((qx(which le.pl)) ne 0) { die "FATAL: le.pl Not found, can't continue!\n"; }

    my @argsarray = (
            '--key $WorkPath/$CSRKey',
            '--csr $WorkPath/$CSRFile',
            '--csr-key $WorkPath/$PriKey',
            '--crt $WorkPath/$CertNameTMP',
            '--domains $Domains',
            '--handle-with Crypt::LE::Challenge::Simple',
            '--handle-as dns',
            '--renew 1',
            '--issue-code=88',
    );
    my $args = join ' ', @argsarray;
    qx(/usr/local/bin/le.pl $args); # Perlception

    # Code 88 will be returned by le.pl if the renewal was successful
    if ( $? eq 88) {
            &AppendRC();
            &GetHash();
            &PushRemote();
    } else {
            die "FATAL: We were within renewal window but le.pl didn't return succesful renewal code: Exiting with failure\n";
    }
}

sub AppendRC {
    open ( FH0, ">>", "$WorkPath/$CertNameTMP" ) || die "Couldn't open $WorkPath/$CertNameTMP\n";
    open ( FH1, "<", "$WorkPath/$RootCert" ) || die "Couldn't open $WorkPath/$RootCert\n";
    while ( my $readline = <FH1> ) { 
        print FH0 $readline;
    }
    close ( FH0 ) || die "Error closing file handle FH0\n";
    close ( FH1 ) || die "Error closing file handle FH1\n";
}

sub PushRemote {
    if ( ( !-T $WorkPath/$HashFile ) || ( !-r $WorkPath/$HashFile ) ) { die "Error: $WorkPath/$HashFile is not found, garbage or not readable: Terminating\n\a"; }
    my $scp = new Net::SCP( $RemoteServer, $RemoteUser );
    $scp->put($WorkPath/$HashFile) || die "Test $scp->{errstr}";
}

sub GetUID {
    my $UIDname = POSIX::cuserid();
    if ( $UIDname ne "root" ) { die "WARN: Script MUST be run with root privileges\n"; }
}

sub Rehash {
    system ( "service unreal stop" );
    sleep (2);
    system ( "service unreal start");
}

sub watchdoggo {
    die "Fatal error! watchdog timer expired: Terminating.\n\a";
}
