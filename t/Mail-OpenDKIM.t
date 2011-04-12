#!/usr/bin/perl -wT

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Mail-OpenDKIM.t'

#########################

use Test::More tests => 16;
use Error qw(:try);
BEGIN { use_ok('Mail::OpenDKIM') };

#########################

OpenDKIM: {

my $msg = <<'EOF';
From: Nigel Horne <njh@example.com>
To: Self <njh@example.com>
Subject: Testing

Can you hear me, Mother?
EOF

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

	$msg =~ s/\n/\r\n/g;

	ok($d->dkim_chunk({ chunkp => $msg, len => length($msg) }) == DKIM_STAT_OK);

	# Flag no more data to come
	ok($d->dkim_chunk({ chunkp => '', len => 0 }) == DKIM_STAT_OK);

	# Will fail because the secret key isn't valid
	ok($d->dkim_eom() == DKIM_STAT_NORESOURCE);

	ok($d->dkim_geterror() eq 'd2i_PrivateKey_bio() failed');

	my $args = {
		initial => 0,
		buf => undef,
		len => undef
	};

	$d->dkim_getsighdr_d($args);

	# diag("Buf = $$args{buf}");

	ok(defined($$args{buf}));
	ok(defined($$args{len}));
	ok(length($$args{len}) > 0);
	like($$args{buf}, qr/a=rsa-sha1/);
	like($$args{buf}, qr/d=example.com/);

	ok($d->dkim_free() == DKIM_STAT_OK);

	$o->dkim_close();

	try {
		$o->dkim_close();
		fail();
	} catch Error with {
		my $ex = shift;
		like($ex, qr/dkim_close called before dkim_init/);
	};
}
