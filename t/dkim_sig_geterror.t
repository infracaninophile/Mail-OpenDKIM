#!/usr/bin/perl -wT

use Test::More tests => 12;
use Error qw(:try);
BEGIN { use_ok('Mail::OpenDKIM') };

#########################

# Version is see to 100 not 1
my $msg = <<'EOF';
DKIM-Signature: v=100; a=rsa-sha1; c=relaxed; d=nh-dev.int.kcilink.com; h=from:to:subject; s=nh-dev; bh=TozDQdcuD/NljOIYtF7AyqaxB8s=; b=dMk1p8wJdpHEFOk2pbtSScD3c2spKGkEo917Plae1weNhdrPvZOWvpZYnQL4/S9iQQtXpUByhjU0ObbWE/SgOhpFS216C847c+3RJCESNMJqxSzf65cuGPLffKQg4dboVKS759wC3hDhIMIPmdLABaK4crFAZcBnl+AQP1QpV4H9jUydiU1CqLURpZgeRd3uqhtua/wJTz3t7ad7YfPhQst7pYD7m97xp0PZURjPTYEKTHSJfhfT4zVDXl1+/HeNc3SV+nT9trpIj9ZOfmhotPYGE1PLX5ZyhZmskff7jQDALJxj6z2jICTCKhwLOtuENf9tCYiyYlMcYuij+hTSBg==
From: Nigel Horne <njh@bandsman.co.uk>
To: Tester <dktest@blackops.org>
Subject: Testing D

Can you hear me, Mother?
EOF

SIG_GETERROR: {

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

	ok($d->dkim_eom() == DKIM_STAT_CANTVRFY);

	$sig = $d->dkim_getsignature();

	ok(defined($sig));

	ok($d->dkim_sig_geterror({ sig => $sig }) == DKIM_SIGERROR_VERSION);

	ok(Mail::OpenDKIM::dkim_sig_geterrorstr(DKIM_SIGERROR_VERSION) eq 'unsupported signature version');

	ok($d->dkim_free() == DKIM_STAT_OK);

	$o->dkim_close();
}
