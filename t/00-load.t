#!perl -T

use Test::More tests => 2;

BEGIN {
    use_ok( 'Mail::OpenDKIM' ) || print "Bail out!";
    use_ok( 'Mail::OpenDKIM::DKIM' ) || print "Bail out!";
}

diag ("Testing Mail::OpenDKIM $Mail::OpenDKIM::VERSION, Perl $], $^X");
diag ("Testing Mail::OpenDKIM::DKIM $Mail::OpenDKIM::DKIM::VERSION, Perl $], $^X");
