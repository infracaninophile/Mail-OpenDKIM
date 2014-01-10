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
	ok($o->dkim_init(),'Init');

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

		ok(defined($d),'sign');

		# d is a Mail::OpenDKIM::DKIM object
	} catch Error with {
		my $ex = shift;
		fail($ex->stringify);
	};

	isa_ok($d, 'Mail::OpenDKIM::DKIM');

	$msg =~ s/\n/\r\n/g;

	ok($d->dkim_chunk({ chunkp => $msg, len => length($msg) }) == DKIM_STAT_OK,'msg chunk');

	# Flag no more data to come
	ok($d->dkim_chunk({ chunkp => '', len => 0 }) == DKIM_STAT_OK,'empty chunk');

	# Will fail because the secret key isn't valid
	ok($d->dkim_eom() == DKIM_STAT_NORESOURCE,'eom');

	ok($d->dkim_geterror() eq 'd2i_PrivateKey_bio() failed','key failure');

	my $args = {
		initial => 0,
		buf => undef,
		len => undef
	};

	my $version = sprintf("%x", Mail::OpenDKIM::dkim_libversion());

	diag($version);

	if($version >= 2040000) {
		# Will fail because the private key failed to load
		ok($d->dkim_getsighdr_d($args) == DKIM_STAT_INVALID,'getsighdr_d');
		like($d->dkim_geterror(), qr/private key load failure/);
		ok(1);
		ok(1);
		ok(1);
	} else {
		ok($d->dkim_getsighdr_d($args) == DKIM_STAT_OK,'getsighdr_d');

		# diag("Buf = $$args{buf}");
		# diag("Len = $$args{len}");

		ok(defined($$args{buf}),'buf');
		ok(defined($$args{len}),'len');
		ok(length($$args{len}) > 0,'len > 0');
		like($$args{buf}, qr/a=rsa-sha1/,'sha1');
		like($$args{buf}, qr/d=example.com/,'example.com');
	}

	ok($d->dkim_free() == DKIM_STAT_OK,'free');

	$o->dkim_close();

	try {
		$o->dkim_close();
		fail();
	} catch Error with {
		my $ex = shift;
		like($ex, qr/dkim_close called before dkim_init/);
	};
}
