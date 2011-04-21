package Mail::OpenDKIM::DKIM;

use 5.010000;
use strict;
use warnings;

use Error;

use Mail::OpenDKIM;

our $VERSION = '0.01';

# Preloaded methods go here.

sub new {
	my ($class, $args) = @_;

	foreach(qw(dkimlib_handle)) {
		exists($$args{$_}) or throw Error::Simple("$class->new missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("$class->new undefined argument '$_'");
	}

	my $self = {
		_dkimlib_handle => $$args{dkimlib_handle},	# DKIM_LIB
		_dkim_handle => undef,	# DKIM
	};

	bless $self, $class;

	return $self;
}

sub dkim_sign
{
	my ($self, $args) = @_;

	if($self->{_dkim_handle}) {
		throw Error::Simple('dkim_sign called twice');
	}

	foreach(qw(id secretkey selector domain hdrcanon_alg bodycanon_alg sign_alg length)) {
		exists($$args{$_}) or throw Error::Simple("dkim_sign missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_sign undefined argument '$_'");
	}

	my $statp;

	$self->{_dkim_handle} = Mail::OpenDKIM::_dkim_sign($self->{_dkimlib_handle},
		$$args{id}, $$args{secretkey}, $$args{selector}, $$args{domain},
		$$args{hdrcanon_alg}, $$args{bodycanon_alg}, $$args{sign_alg},
		$$args{length}, $statp);

	return $statp;
}

sub dkim_verify
{
	my ($self, $args) = @_;

	if($self->{_dkim_handle}) {
		throw Error::Simple('dkim_verify called twice');
	}

	foreach(qw(id)) {
		exists($$args{$_}) or throw Error::Simple("dkim_verify missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_verify undefined argument '$_'");
	}

	my $statp;

	$self->{_dkim_handle} = Mail::OpenDKIM::_dkim_verify($self->{_dkimlib_handle},
		$$args{id}, $statp);

	return $statp;
}

sub dkim_header
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_header called before dkim_sign/dkim_verify');
	}
	foreach(qw(header len)) {
		exists($$args{$_}) or throw Error::Simple("dkim_header missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_header undefined argument '$_'");
	}

	return Mail::OpenDKIM::_dkim_header($self->{_dkim_handle}, $$args{header}, $$args{len});
}

sub dkim_body
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_body called before dkim_sign/dkim_verify');
	}
	foreach(qw(bodyp len)) {
		exists($$args{$_}) or throw Error::Simple("dkim_body missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_body undefined argument '$_'");
	}

	return Mail::OpenDKIM::_dkim_body($self->{_dkim_handle}, $$args{bodyp}, $$args{len});
}

sub dkim_eoh
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_eoh called before dkim_sign/dkim_verify');
	}

	return Mail::OpenDKIM::_dkim_eoh($self->{_dkim_handle});
}

sub dkim_chunk
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_chunk called before dkim_sign/dkim_verify');
	}
	foreach(qw(chunkp len)) {
		exists($$args{$_}) or throw Error::Simple("dkim_chunk missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_chunk undefined argument '$_'");
	}

	return Mail::OpenDKIM::_dkim_chunk($self->{_dkim_handle}, $$args{chunkp}, $$args{len});
}

sub dkim_eom
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_eom called before dkim_sign/dkim_verify');
	}

	return Mail::OpenDKIM::_dkim_eom($self->{_dkim_handle});
}

sub dkim_getsighdr
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_getsighdr called before dkim_sign');
	}
	foreach(qw(initial buf len)) {
		exists($$args{$_}) or throw Error::Simple("dkim_getsighdr missing argument '$_'");
	}

	return Mail::OpenDKIM::_dkim_getsighdr($self->{_dkim_handle}, $$args{buf}, $$args{len}, $$args{initial});
}

sub dkim_getsighdr_d
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_getsighdr_d called before dkim_sign');
	}
	foreach(qw(initial buf len)) {
		exists($$args{$_}) or throw Error::Simple("dkim_getsighdr_d missing argument '$_'");
	}

	my $len;

	my $rc = Mail::OpenDKIM::_dkim_getsighdr_d($self->{_dkim_handle}, $$args{initial}, $$args{buf}, $len);

	if($rc == DKIM_STAT_OK) {
		$$args{len} = $len;
	}

	return $rc;
}

sub dkim_getsignature
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_getsignature called before dkim_verify');
	}

	return Mail::OpenDKIM::_dkim_getsignature($self->{_dkim_handle});
}

sub dkim_getsiglist
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_getsiglist called before dkim_sign/dkim_verify');
	}
	foreach(qw(sigs nsigs)) {
		exists($$args{$_}) or throw Error::Simple("dkim_getsiglist missing argument '$_'");
	}

	my($rc, $nsigs, @sigs) = Mail::OpenDKIM::_dkim_getsiglist($self->{_dkim_handle});

	if($rc == DKIM_STAT_OK) {
		$$args{nsigs} = $nsigs;
		$$args{sigs} = \@sigs;
	} else {
		$$args{nsigs} = undef;
	}

	return $rc;
}

sub dkim_ohdrs
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_ohdrs called before dkim_verify');
	}
	foreach(qw(sig ptrs cnt)) {
		exists($$args{$_}) or throw Error::Simple("dkim_ohdrs missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_ohdrs missing argument '$_'");
	}

	my $cnt = $$args{cnt};

	my $rc = Mail::OpenDKIM::_dkim_ohdrs($self->{_dkim_handle}, $$args{sig}, $$args{ptrs}, $cnt);
	if($rc == DKIM_STAT_OK) {
		$$args{cnt} = $cnt;
	} else {
		$$args{cnt} = undef;
	}

	return $rc;
}

sub dkim_get_signer
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_get_signer called before dkim_sign');
	}

	return Mail::OpenDKIM::_dkim_get_signer($self->{_dkim_handle});
}

sub dkim_set_signer
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_set_signer called before dkim_sign');
	}
	foreach(qw(signer)) {
		exists($$args{$_}) or throw Error::Simple("dkim_set_signer missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_set_signer undefined argument '$_'");
	}

	return Mail::OpenDKIM::_dkim_set_signer($self->{_dkim_handle}, $$args{signer});
}

sub dkim_set_margin
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_set_margin called before dkim_sign');
	}
	foreach(qw(margin)) {
		exists($$args{$_}) or throw Error::Simple("dkim_set_margin missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_set_margin undefined argument '$_'");
	}

	return Mail::OpenDKIM::_dkim_set_margin($self->{_dkim_handle}, $$args{margin});
}

sub dkim_get_user_context
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_get_user_context called before dkim_sign');
	}

	return Mail::OpenDKIM::_dkim_get_user_context($self->{_dkim_handle});
}

sub dkim_set_user_context
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_set_user_context called before dkim_sign');
	}
	foreach(qw(context)) {
		exists($$args{$_}) or throw Error::Simple("dkim_set_final missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_set_final undefined argument '$_'");
	}

	return Mail::OpenDKIM::_dkim_set_user_context($self->{_dkim_handle}, $$args{context});
}

sub dkim_atps_check
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_atps_check called before dkim_verify');
	}
	foreach(qw(sig)) {
		exists($$args{$_}) or throw Error::Simple("dkim_set_final missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_set_final undefined argument '$_'");
	}
	foreach(qw(res timeout)) {
		exists($$args{$_}) or throw Error::Simple("dkim_set_final missing argument '$_'");
	}

	my $res;

	my $rc = Mail::OpenDKIM::_dkim_atps_check($self->{_dkim_handle}, $$args{sig}, $$args{timeout} ? $$args{timeout} : 0, $res);

	if($rc == DKIM_STAT_OK) {
		$$args{res} = $res;
	} else {
		$$args{res} = undef;
	}

	return $rc;
}

sub dkim_diffheaders
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_diffheaders called before dkim_verify');
	}
	foreach(qw(canon maxcost ohdrs nohdrs)) {
		exists($$args{$_}) or throw Error::Simple("dkim_diffheaders missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_diffheaders undefined argument '$_'");
	}

	my $nout;
	my $out;

	my $rc = Mail::OpenDKIM::_dkim_diffheaders($self->{_dkim_handle}, $$args{canon}, $$args{maxcost}, $$args{ohdrs}, $$args{hdrs}, $out, $nout);

	if($rc == DKIM_STAT_OK) {
		$$args{out} = $out;
		$$args{nout} = $nout;
	} else {
		$$args{out} = undef;
		$$args{nout} = undef;
	}

	return $rc;
}

sub dkim_get_reputation
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_get_reputation called before dkim_verify');
	}
	foreach(qw(sig qroot)) {
		exists($$args{$_}) or throw Error::Simple("dkim_get_reputation missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_get_reputation undefined argument '$_'");
	}

	my $rep;

	my $rc = Mail::OpenDKIM::_dkim_get_reputation($self->{_dkim_handle}, $$args{sig}, $$args{qroot}, $rep);

	if($rc == DKIM_STAT_OK) {
		$$args{rep} = $rep;
	} else {
		$$args{rep} = undef;
	}

	return $rc;
}

sub dkim_set_final()
{
	my ($self, $args) = @_;

	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_set_final called before dkim_sign');
	}
	foreach(qw(func)) {
		exists($$args{$_}) or throw Error::Simple("dkim_set_final missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_set_final undefined argument '$_'");
	}

	return Mail::OpenDKIM::_dkim_set_final($self->{_dkimlib_handle}, $$args{func});
}

sub dkim_set_prescreen()
{
	my ($self, $args) = @_;

	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_set_prescreen called before dkim_sign');
	}
	foreach(qw(func)) {
		exists($$args{$_}) or throw Error::Simple("dkim_set_prescreen missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_set_prescreen undefined argument '$_'");
	}

	return Mail::OpenDKIM::_dkim_set_prescreen($self->{_dkimlib_handle}, $$args{func});
}

sub dkim_getpartial
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_getpartial called before dkim_sign');
	}

	return Mail::OpenDKIM::_dkim_getpartial($self->{_dkim_handle});
}

sub dkim_setpartial()
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_setpartial called before dkim_sign');
	}
	foreach(qw(value)) {
		exists($$args{$_}) or throw Error::Simple("dkim_setpartial missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_setpartial undefined argument '$_'");
	}

	return Mail::OpenDKIM::_dkim_setpartial($self->{_dkim_handle}, $$args{value});
}

sub dkim_getdomain
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_getdomain called before dkim_sign/dkim_verify');
	}

	return Mail::OpenDKIM::_dkim_getdomain($self->{_dkim_handle});
}

sub dkim_getuser
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_getuser called before dkim_sign/dkim_verify');
	}

	return Mail::OpenDKIM::_dkim_getuser($self->{_dkim_handle});
}

sub dkim_minbody
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_minbody called before dkim_sign/dkim_verify');
	}

	return Mail::OpenDKIM::_dkim_minbody($self->{_dkim_handle});
}

sub dkim_getmode
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_getmode called before dkim_sign/dkim_verify');
	}

	return Mail::OpenDKIM::_dkim_getmode($self->{_dkim_handle});
}

sub dkim_policy
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_policy called before dkim_verify');
	}

	my ($pcode, $pflags);

	my $rc = Mail::OpenDKIM::_dkim_policy($self->{_dkim_handle}, $pcode, $pflags, $$args{pstate} ? $$args{pstate} : 0);

	if($rc == DKIM_STAT_OK) {
		$$args{pcode} = $pcode;
		$$args{pflags} = $pflags;
	} else {
		$$args{pcode} = undef;
		$$args{pflags} = undef;
	}

	return $rc;
}

sub dkim_policy_state_new
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_policy_state_new called before dkim_verify');
	}

	return Mail::OpenDKIM::_dkim_policy_state_new($self->{_dkim_handle});
}

sub dkim_policy_state_free
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_policy_state_free called before dkim_verify');
	}
	foreach(qw(pstate)) {
		exists($$args{$_}) or throw Error::Simple("dkim_policy_state_free missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_policy_state_free undefined argument '$_'");
	}

	return Mail::OpenDKIM::_dkim_policy_state_free($$args{pstate});
}

sub dkim_policy_getreportinfo
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_policy_getreportinfo called before dkim_verify');
	}

	my $interval = -1;

	my $rc = Mail::OpenDKIM::_dkim_policy_getreportinfo($self->{_dkim_handle},
		$$args{addrbuf} ? $$args{addrbuf} : 0, $$args{addrlen},
		$$args{fmtbuf} ? $$args{fmtbuf} : 0, $$args{fmtlen},
		$$args{optsbuf} ? $$args{optsbuf} : 0, $$args{optslen},
		$$args{smtpbuf} ? $$args{smtpbuf} : 0, $$args{smtplen},
		$interval);

	if($rc == DKIM_STAT_OK) {
		$$args{interval} = $interval;
	}

	return $rc;
}

sub dkim_policy_getdnssec
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_policy_getdnssec called before dkim_verify');
	}

	return Mail::OpenDKIM::_dkim_policy_getdnssec($self->{_dkim_handle});
}

sub dkim_getpresult
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_getpresult called before dkim_verify');
	}

	return Mail::OpenDKIM::_dkim_getpresult($self->{_dkim_handle});
}

sub dkim_sig_getbh
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_sig_getbh called before dkim_verify');
	}
	foreach(qw(sig)) {
		exists($$args{$_}) or throw Error::Simple("dkim_sig_getbh missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_sig_getbh undefined argument '$_'");
	}

	return Mail::OpenDKIM::_dkim_sig_getbh($$args{sig});
}

sub dkim_sig_getcanonlen
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_sig_getcanonlen called before dkim_verify');
	}
	foreach(qw(sig)) {
		exists($$args{$_}) or throw Error::Simple("dkim_sig_getcanonlen missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_sig_getcanonlen undefined argument '$_'");
	}

	my $msglen = $$args{msglen};
	my $canonlen = $$args{canonlen};
	my $signlen = $$args{signlen};

	my $rc = Mail::OpenDKIM::_dkim_sig_getcanonlen($self->{_dkim_handle}, $$args{sig}, $msglen, $canonlen, $signlen);

	if($rc == DKIM_STAT_OK) {
		if(exists($$args{msglen})) {
			$$args{msglen} = $msglen;
		}
		if(exists($$args{canonlen})) {
			$$args{canonlen} = $canonlen;
		}
		if(exists($$args{signlen})) {
			$$args{signlen} = $signlen;
		}
	}

	return $rc;
}

sub dkim_sig_getcanons
{
	my ($self, $args) = @_;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_sig_getcanons called before dkim_verify');
	}

	my $hdr = $$args{hdr};
	my $body = $$args{body};

	my $rc = Mail::OpenDKIM::_dkim_sig_getcanons($$args{sig}, $hdr, $body);

	if($rc == DKIM_STAT_OK) {
		if(exists($$args{hdr})) {
			$$args{hdr} = $hdr;
		}
		if(exists($$args{body})) {
			$$args{body} = $body;
		}
	}

	return $rc;
}

sub dkim_geterror
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_geterror called before dkim_sign/dkim_verify');
	}

	return Mail::OpenDKIM::_dkim_geterror($self->{_dkim_handle});
}

sub dkim_free
{
	my $self = shift;

	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_free called before dkim_sign');
	}

	my $rc = Mail::OpenDKIM::_dkim_free($self->{_dkim_handle});

	if($rc == DKIM_STAT_OK) {
		$self->{_dkim_handle} = undef;
	}

	return $rc;
}

sub DESTROY
{
	my $self = shift;

	if($self->{_dkim_handle}) {
		$self->dkim_free();
	}
}

1;

__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Mail::OpenDKIM::DKIM - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Mail::OpenDKIM::DKIM;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Mail::OpenDKIM, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head1 SUBROUTINES/Methods

=head2 new

For internal use by Mail::OpenDKIM only - do not call directly

=head2 dkim_sign

=head2 dkim_verify

=head2 dkim_header

=head2 dkim_body

=head2 dkim_eoh

=head2 dkim_chunk

=head2 dkim_eom

=head2 dkim_getsighdr

=head2 dkim_getsighdr_d

=head2 dkim_getsiglist

=head2 dkim_get_signer

=head2 dkim_set_signer

=head2 dkim_set_margin

=head2 dkim_get_user_context

=head2 dkim_set_user_context

=head2 dkim_atps_check

=head2 dkim_diffheaders

=head2 dkim_get_reputation

=head2 dkim_set_final

=head2 dkim_set_prescreen

=head2 dkim_getpartial

=head2 dkim_setpartial

=head2 dkim_getdomain

=head2 dkim_getuser

=head2 dkim_minbody

=head2 dkim_getmode

=head2 dkim_policy

=head2 dkim_policy_state_new

=head2 dkim_policy_state_free

The given value of pstate is ignored.
The value sent to libOpenDKIM is always NULL.

=head2 dkim_getpresult

=head2 dkim_geterror

=head2 dkim_free

=head2 EXPORT

All the function names and constants


=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Nigel Horne, E<lt>nigel@kcilink.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by MailerMailer

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
