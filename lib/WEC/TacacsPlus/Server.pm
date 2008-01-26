package WEC::TacacsPlus::Server;
use 5.006;
use strict;
use warnings;
use Carp;

use WEC::TacacsPlus::Connection;

our $VERSION = "0.01";

use base qw(WEC::Server);
# use fields qw(secret);

my $default_options = {
    %{__PACKAGE__->SUPER::default_options},
    Crypt			=> 1,
    OneShot			=> undef,
    Authenticate		=> undef,
    AuthenticateContinue	=> undef,
    Authorize			=> undef,
    Account			=> undef,
};

sub default_options {
    return $default_options;
}

sub connection_class {
    return "WEC::TacacsPlus::Connection";
}

sub init {
    my ($server, $params) = @_;
    $server->{secret}	= delete $params->{Secret};
    utf8::downgrade($server->{secret}, 1) || croak "Wide character in secret";
}

sub secret {
    return shift->{secret};
}


1;
__END__
