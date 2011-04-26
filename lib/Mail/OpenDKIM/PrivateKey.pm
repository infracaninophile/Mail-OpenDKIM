package Mail::OpenDKIM::PrivateKey;

use 5.010000;
use strict;
use warnings;
use Carp;

=head1 NAME

Mail::OpenDKIM::PrivateKey - Load in a private key for use with the Mail::OpenDKIM package

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

Mail::OpenDKIM::PrivateKey provides a system to allow private keys to be loaded from a file
for use when siginging an email with Mail::OpenDKIM::Signer.

It provides enough of a subset of the functionaility of Mail::DKIM::PrivateKey to allow
use of the OpenDKIM library with Mail::OpenDKIM::Signer.

  use Mail::OpenDKIM::PrivateKey;

  my $pk;

  eval {
     $pk = Mail::OpenDKIM::PrivateKey->load(File => 'mykeyfile'));
  }
  if(defined($pk)) {
    # Do something with $pk->data();
    ...
  }

=head1 SUBROUTINES/METHODS

=head2 load

=cut

sub load
{
  my ($class, %args) = @_;

  my $self = {
    _data => undef,
  };

  bless $self, $class;

  if($args{File}) {
    open(my $fin, '<', $args{File}) or croak("Can't open $args{File}: $!");
    while(!eof($fin)) {
      my $line = <$fin>;
      chomp $line;
      unless($line =~ /^---/) {
        $self->{_data} .= $line;
      }
    }
    close $fin;
  }
  elsif($args{Data}) {
    $self->{_data} = $args{Data};
  }

  return $self;
}


=head2 data

This routine provides access to the key data.

=cut

sub data {
  my $self = shift;

  return $self->{_data};
}


=head2 EXPORT

This module exports nothing.

=head1 SEE ALSO

Mail::DKIM::PrivateKey

=head1 NOTES

This module does not yet implement all of the API of Mail::DKIM::PrivateKey

=head1 AUTHOR

Nigel Horne, E<lt>nigel@kcilink.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Nigel Horne

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;

