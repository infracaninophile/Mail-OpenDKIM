#!/usr/bin/perl -wT

use Test::More tests => 9;
use Error qw(:try);
BEGIN { use_ok('Mail::OpenDKIM') };

#########################

DKIM_SET_SIGNER: {

	my $o = new_ok('Mail::OpenDKIM');
	ok($o->dkim_init());

	my $d;

	try {
		$d = $o->dkim_sign({
			id => 'MLM',
			secretkey => '11111',
			selector => 'example',
			domain => 'example.com',
			hdrcanon_alg => DKIM_CANON_RELAXED,
			bodycanon_alg => DKIM_CANON_RELAXED,
			sign_alg => DKIM_SIGN_RSASHA1,
			length => -1,
		});

		ok(defined($d));

		# d is a Mail::OpenDKIM::DKIM object
	} catch Error with {
		my $ex = shift;
		fail($ex->stringify);
	};

	isa_ok($d, 'Mail::OpenDKIM::DKIM');

	ok($d->dkim_set_signer({ signer => '123' }) == DKIM_STAT_OK);

	my $signer = $d->dkim_get_signer();

	ok(defined($signer));
	ok($signer eq '123');

	ok($d->dkim_free() == DKIM_STAT_OK);

	$o->dkim_close();
}

