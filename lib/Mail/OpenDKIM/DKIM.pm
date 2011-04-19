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

sub dkim_geterror
{
	my $self = shift;
	unless($self->{_dkim_handle}) {
		throw Error::Simple('dkim_geterror called before dkim_sign');
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

=head2 dkim_set_final

=head2 dkim_set_prescreen

=head2 dkim_getpartial

=head2 dkim_setpartial

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
