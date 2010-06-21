package WEC::TacacsPlus::Client;
use 5.006;
use strict;
use warnings;
use Carp;

use WEC::TacacsPlus::Connection;
use WEC::TacacsPlus::Constants qw(PORT);

our $VERSION = "1.000";

use base qw(WEC::Client);
# use fields qw(secret);

my $default_options = {
    %{__PACKAGE__->SUPER::default_options},
    OneShot		=> undef,
    Crypt		=> 1,
    AuthenticateResult	=> undef,
    AuthorizeResult	=> undef,
    AccountResult	=> undef,
};

sub default_options {
    return $default_options;
}

sub connection_class {
    return "WEC::TacacsPlus::Connection";
}

sub init {
    (my $client, my $params) = @_;

    $client->{secret} = delete $params->{Secret};
    utf8::downgrade($client->{secret}, 1) || croak "Wide character in secret";
    if (defined $client->{destination}) {
        $client->{destination} = "tcp://" . $client->{destination} unless
            $client->{destination} =~ m!\A\w+://!;
        $client->{destination} .= ":" . PORT if
            $client->{destination} =~ m!\Atcp://[^:]+$!i;
    }
}

sub secret {
    return shift->{secret};
}

sub connect : method {
    my $c = shift->SUPER::connect(shift, shift);
    $c->secret(shift) if @_;
    return $c;
}

1;
__END__
