package Mail::OpenDKIM::Signature;

use 5.010000;
use strict;
use warnings;

use Error qw(:try);
use Carp;

=head1 NAME

Mail::OpenDKIM::Signature - generates a DKIM signature for a message

=head1 SYNOPSIS

  use Mail::DKIM::Signature;

  # create a signer object
  my $dkim = Mail::OpenDKIM::Signature->new(
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

=head1 DESCRIPTION

Mail::OpenDKIM::PrivateKey provides a system to allow private keys to be loaded from a file
for use when siginging an email with Mail::OpenDKIM::Signature.

It provides enough of a subset of the functionaility of Mail::DKIM::PrivateKey to allow
use of the OpenDKIM library with Mail::OpenDKIM::Signature.

=head1 SUBROUTINES/METHODS

=head2 new

=cut

sub new {
  my ($class, %args) = @_;

  my $self = {
  };

  bless $self, $class;

  return $self;
}

sub data
{
  my $self = shift;

  if(@_) {
    $self->{_signature} = shift;
  }

  return $self->{_signature};
}

sub as_string
{
  my $self = shift;

  return 'DKIM-Signature: ' . $self->data();
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Mail::OpenDKIM::Signature - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Mail::OpenDKIM::Signature;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Mail::OpenDKIM::Signature, created by h2xs. It looks like the
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

