#!perl -w

use strict;
use warnings;
use Test::More tests => 2;

BEGIN {
	use_ok('Mail::OpenDKIM');
}

SSL: {
	ok(Mail::OpenDKIM::dkim_getpresultstr(DKIM_PRESULT_NONE) eq 'none');
}
