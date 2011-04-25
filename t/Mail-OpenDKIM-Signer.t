# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Mail-OpenDKIM-Signer.t'

#########################

use Test::More tests => 8;
BEGIN { use_ok('Mail::OpenDKIM::PrivateKey') };
BEGIN { use_ok('Mail::OpenDKIM::Signer') };

#########################

my $pk = Mail::OpenDKIM::PrivateKey->load(File => 't/example.key');

ok(defined($pk));

isa_ok($pk, 'Mail::OpenDKIM::PrivateKey');

my $dkim = new_ok('Mail::OpenDKIM::Signer' => [
		Algorithm => 'rsa-sha1',
		Method => 'relaxed',
		Domain => 'example.com',
		Selector => 'example',
		Key => $pk
	]
);

my $msg = <<'EOF';
From: Nigel Horne <njh@example.com>
To: Tester <dktest@blackops.org>
Subject: Testing O

Can you hear me, Mother?
EOF

$msg =~ s/\n/\r\n/g;

$dkim->PRINT($msg);

$dkim->CLOSE();

my $signature = $dkim->as_string;

ok(defined($signature));

like($signature, qr/a=rsa-sha1/);
like($signature, qr/d=example.com/);
