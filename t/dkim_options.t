#!/usr/bin/perl -wT

use Test::More tests => 5;
BEGIN { use_ok('Mail::OpenDKIM') };

#########################

LIBFEATURE: {

	my $o = new_ok('Mail::OpenDKIM');
	ok($o->dkim_init());

	my $args = {
		op => DKIM_OP_GETOPT,
		opt => DKIM_OPTS_TMPDIR,
		data => pack('B' x 80, 0 x 80),
		len => 80
	};

	ok($o->dkim_options($args) == DKIM_STAT_OK);

	ok(defined($$args{data}));

	$o->dkim_close();
}

