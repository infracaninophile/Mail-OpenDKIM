#!perl -T

use Test::More tests => 5;

BEGIN {
    use_ok( 'Mail::OpenDKIM' ) || print "Bail out!";
    use_ok( 'Mail::OpenDKIM::DKIM' ) || print "Bail out!";
    use_ok( 'Mail::OpenDKIM::PrivateKey' ) || print "Bail out!";
    use_ok( 'Mail::OpenDKIM::Signer' ) || print "Bail out!";
}

my $version = Mail::OpenDKIM::dkim_libversion();
$version = sprintf("%x", $version);
ok($version >= 2030000);	# Needs at least version 2.3

diag ("Testing Mail::OpenDKIM $Mail::OpenDKIM::VERSION, Perl $], OpenDKIM $version, $^X");
