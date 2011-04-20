#!perl -w

use strict;
use warnings;
use Test::More tests => 3;

BEGIN {
	use_ok('Mail::OpenDKIM');
}

GETPOLICYSTR: {
	my $v = Mail::OpenDKIM::dkim_getpolicystr(DKIM_POLICY_ALL);

	ok(defined($v));
	ok($v eq 'all');
}
