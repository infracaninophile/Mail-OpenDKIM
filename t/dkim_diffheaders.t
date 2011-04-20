#!/usr/bin/perl -wT

use Test::More tests => 13;
use Error qw(:try);
BEGIN { use_ok('Mail::OpenDKIM') };

#########################

my $msg = <<'EOF';
DKIM-Signature: v=1; a=rsa-sha1; c=relaxed; d=nh-dev.int.kcilink.com; h=from:to:subject; s=nh-dev; bh=TozDQdcuD/NljOIYtF7AyqaxB8s=; b=dMk1p8wJdpHEFOk2pbtSScD3c2spKGkEo917Plae1weNhdrPvZOWvpZYnQL4/S9iQQtXpUByhjU0ObbWE/SgOhpFS216C847c+3RJCESNMJqxSzf65cuGPLffKQg4dboVKS759wC3hDhIMIPmdLABaK4crFAZcBnl+AQP1QpV4H9jUydiU1CqLURpZgeRd3uqhtua/wJTz3t7ad7YfPhQst7pYD7m97xp0PZURjPTYEKTHSJfhfT4zVDXl1+/HeNc3SV+nT9trpIj9ZOfmhotPYGE1PLX5ZyhZmskff7jQDALJxj6z2jICTCKhwLOtuENf9tCYiyYlMcYuij+hTSBg==
From: Nigel Horne <njh@bandsman.co.uk>
To: Tester <dktest@blackops.org>
Subject: Testing D

Can you hear me, Mother?
EOF

DIFFHEADERS: {

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

	isa_ok($d, 'Mail::OpenDKIM::DKIM');

	$msg =~ s/\n/\r\n/g;

	ok($d->dkim_chunk({ chunkp => $msg, len => length($msg)}) == DKIM_STAT_OK);

	ok($d->dkim_chunk({ chunkp => '', len => 0}) == DKIM_STAT_OK);

	my $args = {
		sigs => undef,
		nsigs => undef
	};

	ok($d->dkim_getsiglist($args) == DKIM_STAT_OK);

	ok($$args{nsigs} == 1);

	ok($d->dkim_eom() == DKIM_STAT_OK);

	my @sigs = @{$$args{sigs}};
	my @ptrs = [ '', '', '', '', '' ];

	$args = {
		sig => $sigs[0],
		ptrs => \@ptrs,
		cnt => 5
	};

	# FIXME: Fails with sig is not of type DKIM_SIGINFO, which most likely means that
	#	either it or dkim_getsiglist (or both) aren't working
	TODO: {
		todo_skip 'dkim_ohdrs fails with sig is not of type DKIM_SIGINFO - skip until dkim_getsiglist is fixed', 2;
		ok($d->dkim_ohdrs($args) == DKIM_STAT_OK);

		my $cnt = $$args{cnt};

		$args = {
			canon => DKIM_CANON_RELAXED,
			maxcost => 2,
			ohdrs => \@ptrs,
			nohdrs => $cnt,
		};

		ok($d->dkim_diffheaders($args) == DKIM_STAT_OK);
	}

	ok($d->dkim_free() == DKIM_STAT_OK);

	$o->dkim_close();
}
