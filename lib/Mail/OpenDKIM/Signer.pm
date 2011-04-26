package Mail::OpenDKIM::Signer;

use 5.010000;
use strict;
use warnings;

use Error qw(:try);
use Carp;
use Mail::OpenDKIM;
use Mail::OpenDKIM::PrivateKey;	# Including this allows callers to only include Signer.pm

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Mail::OpenDKIM::Signer ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01';

# Preloaded methods go here.
sub new {
	my ($class, %args) = @_;

	my $self = {
	};

	my $algorithm;

	if(!$args{Algorithm}) {
		croak('Missing algorithm');
	}
	elsif($args{Algorithm} eq 'rsa-sha1') {
		$algorithm = DKIM_SIGN_RSASHA1;
	}
	elsif($args{Algorithm} eq 'rsa-sha256') {
		$algorithm = DKIM_SIGN_RSASHA256;
	}
	else {
		croak("Unsupported algorithm: $args{Algorithm}");
	}

	my ($h, $b);

	if(!$args{Method}) {
		croak('Missing method');
	}
	elsif($args{Method} =~ /(.+)\/(.+)/) {
		$h = $1;
		$b = $2;
	}
	else {
		$h = $args{Method};
		$b = $h;
	}

	my ($hdrcanon_alg, $bodycanon_alg);

	if($h eq 'relaxed') {
		$hdrcanon_alg = DKIM_CANON_RELAXED;
	}
	elsif($h eq 'simple') {
		$hdrcanon_alg = DKIM_CANON_SIMPLE;
	}
	else {
		croak("Unsupported method: $h");
	}

	if($b eq 'relaxed') {
		$bodycanon_alg = DKIM_CANON_RELAXED;
	}
	elsif($b eq 'simple') {
		$bodycanon_alg = DKIM_CANON_SIMPLE;
	}
	else {
		croak("Unsupported method: $b");
	}

	my $oh = Mail::OpenDKIM->new();

	$oh->dkim_init();

	my $signer;

	try {
		$signer = $oh->dkim_sign({
			id => 'MLM',
			secretkey => $args{Key}->data,
			selector => $args{Selector},
			domain => $args{Domain},
			hdrcanon_alg => $hdrcanon_alg,
			bodycanon_alg => $bodycanon_alg,
			sign_alg => $algorithm,
			length => -1
		});
	} catch Error with {
		my $ex = shift;
		croak($ex->stringify);
	};

	$self->{_dkim_handle} = $oh;	# Mail::OpenDKIM object
	$self->{_signer} = $signer;	# Mail::OpenDKIM::DKIM object

	bless $self, $class;

	return $self;
}

sub PRINT
{
	my $self = shift;

	return unless(@_);

	my $signer = $self->{_signer};

	foreach(@_) {
		$signer->dkim_chunk({ chunkp => $_, len => length($_) });
	}
}

sub CLOSE
{
	my $self = shift;

	my $signer = $self->{_signer};

	$signer->dkim_chunk({ chunkp => '', len => 0 });

	if($signer->dkim_eom() != DKIM_STAT_OK) {
		croak($signer->dkim_geterror());
	}
}

sub as_string
{
	my $self = shift;

	my $signer = $self->{_signer};

	my $args = {
		initial => 0,
		buf => undef,
		len => undef
	};

	$signer->dkim_getsighdr_d($args);

	return $$args{buf};
}

sub DESTROY
{
	my $self = shift;

	if($self->{_signer}) {
		$self->{_signer}->dkim_free();
	}
	if($self->{_dkimlib_handle}) {
		$self->{_dkimlib_handle}->dkim_close();
	}
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Mail::OpenDKIM::Signer - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Mail::OpenDKIM::Signer;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Mail::OpenDKIM::Signer, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



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

Copyright (C) 2011 by Nigel Horne

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
