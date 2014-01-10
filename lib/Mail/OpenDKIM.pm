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

# This allows declaration  use Mail::OpenDKIM ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(

) ] );

use constant DKIM_CANON_SIMPLE => 0;  # RFC4871
use constant DKIM_CANON_RELAXED => 1;  # RFC4871
use constant DKIM_CANON_DEFAULT => DKIM_CANON_SIMPLE;

use constant DKIM_SIGN_RSASHA1 => 0;
use constant DKIM_SIGN_RSASHA256 => 1;

use constant DKIM_STAT_OK => 0;  # dkim.h
use constant DKIM_STAT_BADSIG => 1;
use constant DKIM_STAT_NOSIG => 2;
use constant DKIM_STAT_NOKEY => 3;
use constant DKIM_STAT_CANTVRFY => 4;
use constant DKIM_STAT_SYNTAX => 5;
use constant DKIM_STAT_NORESOURCE => 6;
use constant DKIM_STAT_INVALID => 9;
use constant DKIM_STAT_NOTIMPLEMENT => 10;

use constant DKIM_MODE_UNKNOWN => -1;
use constant DKIM_MODE_SIGN => 0;
use constant DKIM_MODE_VERIFY => 1;

use constant DKIM_POLICY_NONE => -1;
use constant DKIM_POLICY_UNKNOWN => 0;
use constant DKIM_POLICY_ALL => 1;
use constant DKIM_POLICY_DISCARDABLE => 2;

use constant DKIM_PRESULT_NONE => -1;
use constant DKIM_PRESULT_NXDOMAIN => 0;
use constant DKIM_PRESULT_FOUND => 1;

use constant DKIM_DNSSEC_UNKNOWN => -1;

use constant DKIM_SIGBH_UNTESTED => -1;
use constant DKIM_SIGBH_MATCH => 0;
use constant DKIM_SIGBH_MISMATCH => 1;

use constant DKIM_SIGERROR_VERSION => 1;

use constant DKIM_FEATURE_DIFFHEADERS => 0;
use constant DKIM_FEATURE_DKIM_REPUTATION => 1;
use constant DKIM_FEATURE_PARSE_TIME => 2;
use constant DKIM_FEATURE_QUERY_CACHE => 3;
use constant DKIM_FEATURE_SHA256 => 4;
use constant DKIM_FEATURE_OVERSIGN => 5;
use constant DKIM_FEATURE_DNSSEC => 6;
use constant DKIM_FEATURE_RESIGN => 7;
use constant DKIM_FEATURE_ATPS => 8;

use constant DKIM_SIGFLAG_IGNORE => 1;

use constant DKIM_OP_GETOPT => 0;
use constant DKIM_OP_SETOPT => 1;

use constant DKIM_OPTS_FLAGS => 0;
use constant DKIM_OPTS_TMPDIR => 1;

use constant DKIM_LIBFLAGS_FIXCRLF => 0x0100;

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
  DKIM_CANON_RELAXED
  DKIM_CANON_SIMPLE

  DKIM_SIGN_RSASHA1
  DKIM_SIGN_RSASHA256

  DKIM_STAT_OK
  DKIM_STAT_BADSIG
  DKIM_STAT_NOSIG
  DKIM_STAT_NOKEY
  DKIM_STAT_CANTVRFY
  DKIM_STAT_SYNTAX
  DKIM_STAT_NORESOURCE
  DKIM_STAT_INVALID
  DKIM_STAT_NOTIMPLEMENT

  DKIM_MODE_UNKNOWN
  DKIM_MODE_SIGN
  DKIM_MODE_VERIFY

  DKIM_POLICY_NONE
  DKIM_POLICY_UNKNOWN
  DKIM_POLICY_ALL
  DKIM_POLICY_DISCARDABLE

  DKIM_DNSSEC_UNKNOWN

  DKIM_SIGBH_UNTESTED
  DKIM_SIGBH_MATCH
  DKIM_SIGBH_MISMATCH

  DKIM_SIGERROR_VERSION

  DKIM_PRESULT_NONE
  DKIM_PRESULT_NXDOMAIN
  DKIM_PRESULT_FOUND

  DKIM_FEATURE_DIFFHEADERS
  DKIM_FEATURE_DKIM_REPUTATION
  DKIM_FEATURE_PARSE_TIME
  DKIM_FEATURE_QUERY_CACHE
  DKIM_FEATURE_SHA256
  DKIM_FEATURE_OVERSIGN
  DKIM_FEATURE_DNSSEC
  DKIM_FEATURE_RESIGN
  DKIM_FEATURE_ATPS

  DKIM_SIGFLAG_IGNORE

  DKIM_OP_GETOPT
  DKIM_OP_SETOPT

  DKIM_OPTS_FLAGS
  DKIM_OPTS_TMPDIR

  DKIM_LIBFLAGS_FIXCRLF
);

use vars qw($VERSION);
$VERSION = sprintf "%d", q$Revision$ =~ /(\d+)/;

require XSLoader;
XSLoader::load('Mail::OpenDKIM', $VERSION);

=pod

=head1 NAME

Mail::OpenDKIM - Provides an interface to libOpenDKIM

=head1 SYNOPSIS

 # sign outgoing message

 use Mail::DKIM::Signer;

 # create a signer object
 my $dkim = Mail::OpenDKIM::Signer->new(
  Algorithm => 'rsa-sha1',
  Method => 'relaxed',
  Domain => 'example.org',
  Selector => 'selector1',
  KeyFile => 'private.key',
 );

 # read an email and pass it into the signer, one line at a time
 while(<STDIN>) {
  # remove local line terminators
  chomp;
  s/\015$//;

  # use SMTP line terminators
  $dkim->PRINT("$_\015\012");
 }
 $dkim->CLOSE();

 # what is the signature result?
 my $signature = $dkim->signature;
 print $signature->as_string;

 # check validity of incoming message
 my $o = Mail::OpenDKIM->new();
 $o->dkim_init();

 my $d = $o->dkim_verify({
  id => 'MLM',
 });

 $msg =~ s/\n/\r\n/g;

 $d->dkim_chunk({ chunkp => $msg, len => length($msg) });

 $d->dkim_chunk({ chunkp => '', len => 0 });

 $d->dkim_eom();

 my $sig = $d->dkim_getsignature();

 $d->dkim_sig_process({ sig => $sig });

 printf "0x\n", $d->dkim_sig_getflags({ sig => $sig });

 $d->dkim_free();

 $o->dkim_close();

=head1 DESCRIPTION

Mail::OpenDKIM, coupled with Mail::OpenDKIM::DKIM, provides a means of
calling libOpenDKIM from Perl.  Mail::OpenDKIM implements those
routine taking a DKIM_LIB argument; those taking a DKIM argument have
been implemented in Mail::OpenDKIM::DKIM.

Mail::OpenDKIM::Signer provides a drop in replacement for the
signature process provided by Mail::DKIM::Signer.

When an error is encountered, an Error::Simple object is thrown.

=head1 SUBROUTINES/METHODS

=head2 new

Create a new signing/verifying object.
After doing this you will need to call the dkim_init method before you can do much else.

=cut

sub new {
  my $class = shift;

  my $self = {
    _dkimlib_handle => undef,  # DKIM_LIB
  };

  bless $self, $class;

  return $self;
}

=head2 dkim_init

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

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

=head2 dkim_close

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_close
{
  my $self = shift;

  unless($self->{_dkimlib_handle}) {
    throw Error::Simple('dkim_close called before dkim_init');
  }
  _dkim_close($self->{_dkimlib_handle});
  $self->{_dkimlib_handle} = undef;
}

=head2 dkim_flush_cache

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_flush_cache
{
  my $self = shift;

  unless($self->{_dkimlib_handle}) {
    throw Error::Simple('dkim_flush_cache called before dkim_init');
  }
  return _dkim_flush_cache($self->{_dkimlib_handle});
}

=head2 dkim_libfeature

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

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

=head2 dkim_sign

For further information, refer to http://www.opendkim.org/libopendkim/

Returns a Mail::OpenDKIM::DKIM object.

=cut

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

=head2 dkim_verify

For further information, refer to http://www.opendkim.org/libopendkim/

Returns a Mail::OpenDKIM::DKIM object.
The memclosure argument is ignored.

=cut

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

=head2 dkim_getcachestats

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_getcachestats
{
  my ($self, $args) = @_;

  if (dkim_libversion() >= 0x02080000) {
    unless($self->{_dkimlib_handle}) {
      throw Error::Simple('dkim_set_dns_callback called before dkim_init');
    }
    return _dkim_getcachestats($self->{_dkimlib_handle}, $$args{queries}, $$args{hits}, $$args{expired}, $$args{keys});
  } else {
    return _dkim_getcachestats($$args{queries}, $$args{hits}, $$args{expired});
  }
}

=head2 dkim_set_dns_callback

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_set_dns_callback
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

=head2 dkim_set_key_lookup

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_set_key_lookup
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

=head2 dkim_set_policy_lookup

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_set_policy_lookup
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

=head2 dkim_set_signature_handle

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_set_signature_handle
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

=head2 dkim_set_signature_handle_free

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_set_signature_handle_free
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

=head2 dkim_set_signature_tagvalues

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_set_signature_tagvalues
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

=head2 dkim_dns_set_query_cancel

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_dns_set_query_cancel
{
  my ($self, $args) = @_;

  unless($self->{_dkimlib_handle}) {
    throw Error::Simple('dkim_dns_set_query_cancel called before dkim_sign/dkim_verify');
  }
  foreach(qw(func)) {
    exists($$args{$_}) or throw Error::Simple("dkim_dns_set_query_cancel missing argument '$_'");
    defined($$args{$_}) or throw Error::Simple("dkim_dns_set_query_cancel undefined argument '$_'");
  }

  return _dkim_dns_set_query_cancel($self->{_dkimlib_handle}, $$args{func});
}

=head2 dkim_dns_set_query_service

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_dns_set_query_service
{
  my ($self, $args) = @_;

  unless($self->{_dkimlib_handle}) {
    throw Error::Simple('dkim_dns_set_query_service called before dkim_sign/dkim_verify');
  }
  foreach(qw(func)) {
    exists($$args{$_}) or throw Error::Simple("dkim_dns_set_query_service missing argument '$_'");
    defined($$args{$_}) or throw Error::Simple("dkim_dns_set_query_service undefined argument '$_'");
  }

  return _dkim_dns_set_query_service($self->{_dkimlib_handle}, $$args{func});
}

=head2 dkim_dns_set_query_start

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_dns_set_query_start
{
  my ($self, $args) = @_;

  unless($self->{_dkimlib_handle}) {
    throw Error::Simple('dkim_dns_set_query_start called before dkim_sign/dkim_verify');
  }
  foreach(qw(func)) {
    exists($$args{$_}) or throw Error::Simple("dkim_dns_set_query_start missing argument '$_'");
    defined($$args{$_}) or throw Error::Simple("dkim_dns_set_query_start undefined argument '$_'");
  }

  return _dkim_dns_set_query_start($self->{_dkimlib_handle}, $$args{func});
}

=head2 dkim_dns_set_query_waitreply

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_dns_set_query_waitreply
{
  my ($self, $args) = @_;

  unless($self->{_dkimlib_handle}) {
    throw Error::Simple('dkim_dns_set_query_waitreply called before dkim_sign/dkim_verify');
  }
  foreach(qw(func)) {
    exists($$args{$_}) or throw Error::Simple("dkim_dns_set_query_waitreply missing argument '$_'");
    defined($$args{$_}) or throw Error::Simple("dkim_dns_set_query_waitreply undefined argument '$_'");
  }

  return _dkim_dns_set_query_waitreply($self->{_dkimlib_handle}, $$args{func});
}

=head2 dkim_options

For further information, refer to http://www.opendkim.org/libopendkim/

=cut

sub dkim_options
{
  my ($self, $args) = @_;

  unless($self->{_dkimlib_handle}) {
    throw Error::Simple('dkim_options called before dkim_sign/dkim_verify');
  }
  foreach(qw(op opt data len)) {
    exists($$args{$_}) or throw Error::Simple("dkim_options missing argument '$_'");
    defined($$args{$_}) or throw Error::Simple("dkim_options undefined argument '$_'");
  }

  return _dkim_options($self->{_dkimlib_handle}, $$args{op}, $$args{opt}, $$args{data}, $$args{len});
}

sub DESTROY
{
  my $self = shift;

  if ($self->{_dkimlib_handle}) {
    $self->dkim_close();
  }
}

=head2 dkim_libversion

Static method.

=head2 dkim_getcachestats

Static method.

=head1 EXPORT

Many DKIM_* constants, e.g. DKIM_STAT_OK are exported.

=head1 SEE ALSO

Mail::DKIM

http://www.opendkim.org/libopendkim/

RFC 4870, RFC 4871

=head1 DEPENDENCIES

This module requires these other modules and libraries:

  Test::More
  libOpenDKIM 2.3 (http://www.opendkim.org/libopendkim/)
  C compiler

=head1 NOTES

Tested against libOpenDKIM 2.3.1. Known to fail to compile against 2.2.

Only portions of Mail::DKIM::Signer interface, and the support for it,
have been implemented.

Please report any bugs or feature requests to C<bug-mail-opendkim at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Mail-OpenDKIM>.
I will be notified, and then you'll automatically be notified of progress on your bug as I make changes.

The signature creation rountines have been tested more thoroughly than
the signature verification routines.

Feedback will be greatfully received.

=head1 AUTHOR

Nigel Horne

Vick Khera, C<< <vivek at khera.org> >>

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Mail::OpenDKIM

You can also look for information at:

=over 4

=item * MailerMailer Project page

L<http://www.mailermailer.com/labs/projects/Mail-OpenDKIM.rwp>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Mail-OpenDKIM>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Mail-OpenDKIM>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Mail-OpenDKIM>

=item * Search CPAN

L<http://search.cpan.org/dist/Mail-OpenDKIM/>

=back


=head1 SPONSOR

This code has been developed under sponsorship of MailerMailer LLC,
http://www.mailermailer.com/

=head1 COPYRIGHT AND LICENCE

This module is Copyright 2014 Khera Communications, Inc.
It is licensed under the same terms as Perl itself.

=cut

1;
