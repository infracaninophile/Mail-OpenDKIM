#!perl -w

use strict;
use warnings;
use Error qw(:try);
use Test::More tests => 6;

BEGIN {
	use_ok('Mail::OpenDKIM');
}

GETPRESULT: {

	my $o = new_ok('Mail::OpenDKIM');
	ok($o->dkim_init());

	my $d;

	try {
		$d = $o->dkim_verify({
			id => 'MLM',
		});

		ok(defined($d));

		# d is a Mail::OpenDKIM::DKIM object
	} catch Error with {
		my $ex = shift;
		fail($ex->stringify);
	};

	ok($d->dkim_getpresult() == DKIM_PRESULT_NONE);

	ok($d->dkim_free() == DKIM_STAT_OK);

	$o->dkim_close();
}
