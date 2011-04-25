#!perl -w

use strict;
use warnings;
use Error qw(:try);
use Test::More tests => 7;

BEGIN {
	use_ok('Mail::OpenDKIM');
}

POLICY_SYNTAX: {

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

	my $policy = 'fred';
	ok($d->dkim_policy_syntax({ str => $policy, len => length($policy) }) == DKIM_STAT_SYNTAX);

	TODO: {
		local $TODO = 'dkim_policy_syntax returns syntax error on valid policy';

		$policy = 't=y\; o=-';
		ok($d->dkim_policy_syntax({ str => $policy, len => length($policy) }) == DKIM_STAT_OK);
	};

	ok($d->dkim_free() == DKIM_STAT_OK);

	$o->dkim_close();
}

