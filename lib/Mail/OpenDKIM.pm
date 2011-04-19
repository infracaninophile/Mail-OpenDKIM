package Mail::OpenDKIM;

use 5.010000;
use strict;
use warnings;

use Error;
require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Mail::OpenDKIM ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(

) ] );

use constant DKIM_CANON_SIMPLE => 0;	# RFC4871
use constant DKIM_CANON_RELAXED => 1;	# RFC4871
use constant DKIM_CANON_DEFAULT => DKIM_CANON_SIMPLE;

use constant DKIM_SIGN_RSASHA1 => 0;
use constant DKIM_SIGN_RSASHA256 => 1;

use constant DKIM_STAT_OK => 0;	# dkim.h
use constant DKIM_STAT_NORESOURCE => 6;
use constant DKIM_STAT_INVALID => 9;
use constant DKIM_STAT_NOTIMPLEMENT => 10;

use constant DKIM_FEATURE_DIFFHEADERS => 0;
use constant DKIM_FEATURE_DKIM_REPUTATION => 1;
use constant DKIM_FEATURE_PARSE_TIME => 2;
use constant DKIM_FEATURE_QUERY_CACHE => 3;
use constant DKIM_FEATURE_SHA256 => 4;
use constant DKIM_FEATURE_OVERSIGN => 5;
use constant DKIM_FEATURE_DNSSEC => 6;
use constant DKIM_FEATURE_RESIGN => 7;
use constant DKIM_FEATURE_ATPS => 8;

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	DKIM_CANON_RELAXED
	DKIM_CANON_SIMPLE
	DKIM_SIGN_RSASHA1
	DKIM_SIGN_RSASHA256

	DKIM_STAT_OK
	DKIM_STAT_NORESOURCE
	DKIM_STAT_INVALID
	DKIM_STAT_NOTIMPLEMENT

	DKIM_FEATURE_DIFFHEADERS
	DKIM_FEATURE_DKIM_REPUTATION
	DKIM_FEATURE_PARSE_TIME
	DKIM_FEATURE_QUERY_CACHE
	DKIM_FEATURE_SHA256
	DKIM_FEATURE_OVERSIGN
	DKIM_FEATURE_DNSSEC
	DKIM_FEATURE_RESIGN
	DKIM_FEATURE_ATPS
);

our $VERSION = '0.01';

require XSLoader;
XSLoader::load('Mail::OpenDKIM', $VERSION);

# Preloaded methods go here.
sub new {
	my $class = shift;

	my $self = {
		_dkimlib_handle => undef,	# DKIM_LIB
	};

	bless $self, $class;

	return $self;
}

sub dkim_init
{
	my $self = shift;

	if($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_init called more than once');
	}
	$self->{_dkimlib_handle} = _dkim_init();
	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_init failed to create a handle');
	}

	return $self;
}

sub dkim_close
{
	my $self = shift;

	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_close called before dkim_init');
	}
	_dkim_close($self->{_dkimlib_handle});
	$self->{_dkimlib_handle} = undef;
}

sub dkim_flush_cache
{
	my $self = shift;

	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_flush_cache called before dkim_init');
	}
	return _dkim_flush_cache($self->{_dkimlib_handle});
}

sub dkim_libfeature
{
	my ($self, $args) = @_;

	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_libfeature called before dkim_init');
	}
	foreach(qw(feature)) {
		exists($$args{$_}) or throw Error::Simple("dkim_libfeature missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_libfeature undefined argument '$_'");
	}

	return _dkim_libfeature($self->{_dkimlib_handle}, $$args{feature});
}

sub dkim_sign
{
	my ($self, $args) = @_;

	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_sign called before dkim_init');
	}
	foreach(qw(id secretkey selector domain hdrcanon_alg bodycanon_alg sign_alg length)) {
		exists($$args{$_}) or throw Error::Simple("dkim_sign missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_sign undefined argument '$_'");
	}
	require Mail::OpenDKIM::DKIM;

	my $dkim = Mail::OpenDKIM::DKIM->new({ dkimlib_handle => $self->{_dkimlib_handle} });

	my $statp = $dkim->dkim_sign($args);

	unless($statp == DKIM_STAT_OK) {
		throw Error::Simple("dkim_sign failed with status $statp");
	}

	return $dkim;
}

sub dkim_verify
{
	my ($self, $args) = @_;

	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_verify called before dkim_init');
	}
	foreach(qw(id)) {
		exists($$args{$_}) or throw Error::Simple("dkim_verify missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_verify undefined argument '$_'");
	}
	require Mail::OpenDKIM::DKIM;

	my $dkim = Mail::OpenDKIM::DKIM->new({ dkimlib_handle => $self->{_dkimlib_handle} });

	my $statp = $dkim->dkim_verify($args);

	unless($statp == DKIM_STAT_OK) {
		throw Error::Simple("dkim_verify failed with status $statp");
	}

	return $dkim;
}

sub dkim_getcachestats
{
	my ($self, $args) = @_;

	return _dkim_getcachestats($$args{queries}, $$args{hits}, $$args{expired});
}

sub dkim_set_dns_callback()
{
	my ($self, $args) = @_;

	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_set_dns_callback called before dkim_init');
	}
	foreach(qw(func interval)) {
		exists($$args{$_}) or throw Error::Simple("dkim_set_dns_callback missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_set_dns_callback undefined argument '$_'");
	}

	return _dkim_set_dns_callback($self->{_dkimlib_handle}, $$args{func}, $$args{interval});
}

sub dkim_set_key_lookup()
{
	my ($self, $args) = @_;

	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_set_key_lookup called before dkim_sign/dkim_verify');
	}
	foreach(qw(func)) {
		exists($$args{$_}) or throw Error::Simple("dkim_set_key_lookup missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_set_key_lookup undefined argument '$_'");
	}

	return _dkim_set_key_lookup($self->{_dkimlib_handle}, $$args{func});
}

sub dkim_set_policy_lookup()
{
	my ($self, $args) = @_;

	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_set_policy_lookup called before dkim_sign/dkim_verify');
	}
	foreach(qw(func)) {
		exists($$args{$_}) or throw Error::Simple("dkim_set_policy_lookup missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_set_policy_lookup undefined argument '$_'");
	}

	return _dkim_set_policy_lookup($self->{_dkimlib_handle}, $$args{func});
}

sub dkim_set_signature_handle()
{
	my ($self, $args) = @_;

	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_set_signature_handle called before dkim_sign/dkim_verify');
	}
	foreach(qw(func)) {
		exists($$args{$_}) or throw Error::Simple("dkim_set_signature_handle missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_set_signature_handle undefined argument '$_'");
	}

	return _dkim_set_signature_handle($self->{_dkimlib_handle}, $$args{func});
}

sub dkim_set_signature_handle_free()
{
	my ($self, $args) = @_;

	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_set_signature_handle_free called before dkim_sign/dkim_verify');
	}
	foreach(qw(func)) {
		exists($$args{$_}) or throw Error::Simple("dkim_set_signature_handle_free missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_set_signature_handle_free undefined argument '$_'");
	}

	return _dkim_set_signature_handle_free($self->{_dkimlib_handle}, $$args{func});
}

sub dkim_set_signature_tagvalues()
{
	my ($self, $args) = @_;

	unless($self->{_dkimlib_handle}) {
		throw Error::Simple('dkim_set_signature_tagvalues called before dkim_sign/dkim_verify');
	}
	foreach(qw(func)) {
		exists($$args{$_}) or throw Error::Simple("dkim_set_signature_tagvalues missing argument '$_'");
		defined($$args{$_}) or throw Error::Simple("dkim_set_signature_tagvalues undefined argument '$_'");
	}

	return _dkim_set_signature_tagvalues($self->{_dkimlib_handle}, $$args{func});
}

sub DESTROY
{
	my $self = shift;

	if($self->{_dkimlib_handle}) {
		$self->dkim_close();
	}
}

1;

__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Mail::OpenDKIM - Perl interface to the OpenDKIM library

=head1 SYNOPSIS

  use Mail::OpenDKIM;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Mail::OpenDKIM, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head1 SUBROUTINES/Methods

=head2 new

=head2 dkim_init

=head2 dkim_close

=head2 dkim_flush_cache

=head2 dkim_libfeature

=head2 dkim_sign

Returns a Mail::OpenDKIM::DKIM object.

=head2 dkim_verify

Returns a Mail::OpenDKIM::DKIM object.
The memclosure argument is ignored.

=head2 dkim_ssl_version

=head2 dkim_libversion

Static method.

=head2 dkim_getcachestats

Static method.

=head2 dkim_set_dns_callback

=head2 dkim_set_dns_callback

=head2 dkim_set_key_lookup

=head2 dkim_set_policy_lookup

=head2 dkim_set_signature_handle

=head2 dkim_set_signature_handle_free

=head2 dkim_set_signature_tagvalues

=head2 EXPORT

All the function names and constants


=head1 SEE ALSO

http://www.opendkim.org/libopendkim/

=head1 AUTHOR

Nigel Horne, E<lt>nigel@kcilink.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by MailerMailer

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
