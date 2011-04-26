#!perl -wT

use Test::More tests => 6;

BEGIN {
    use_ok( 'Mail::OpenDKIM' ) || print "Bail out!";
    use_ok( 'Mail::OpenDKIM::DKIM' ) || print "Bail out!";
    use_ok( 'Mail::OpenDKIM::PrivateKey' ) || print "Bail out!";
    use_ok( 'Mail::OpenDKIM::Signature' ) || print "Bail out!";
    use_ok( 'Mail::OpenDKIM::Signer' ) || print "Bail out!";
}

my $version = sprintf("%x", Mail::OpenDKIM::dkim_libversion());
ok($version >= 2030000);	# Needs at least version 2.3

diag ("Testing Mail::OpenDKIM $Mail::OpenDKIM::VERSION, Perl $], OpenDKIM $version, $^X");
