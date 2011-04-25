#!perl -T

use Test::More tests => 4;

BEGIN {
    use_ok( 'Mail::OpenDKIM' ) || print "Bail out!";
    use_ok( 'Mail::OpenDKIM::DKIM' ) || print "Bail out!";
    use_ok( 'Mail::OpenDKIM::PrivateKey' ) || print "Bail out!";
}

my $version = Mail::OpenDKIM::dkim_libversion();
ok($version > 0);
$version = sprintf("%x", $version);

diag ("Testing Mail::OpenDKIM $Mail::OpenDKIM::VERSION, Perl $], OpenDKIM $version, $^X");
