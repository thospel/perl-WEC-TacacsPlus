package WEC::TacacsPlus::Connection;
use 5.008_001;	# Otherwise you will hit a closure leak
use Scalar::Util qw(dualvar);
use strict;
use warnings;
use Carp;
use Digest::MD5 qw(md5);

use WEC::TacacsPlus::Constants qw(:Session :HeaderFlags);
use WEC::TacacsPlus::Session;
use WEC::Connection qw(SERVER CLIENT);

our $VERSION = "0.01";

use base qw(WEC::Connection);
# use fields qw(secret header);

our @EXPORT_OK	= qw(@server_flow_class @client_flow_class);
our @CARP_NOT	= qw(WEC::FieldConnection);

use constant {
    VERSION		=> 0xc,
    # Number of bytes needed to determine full record length
    PRE_RECORD		=> 12,

    MAX_SESSIONS	=> 1000,
    # Longest posible message (authorization response, is 252 shorter in fact)
    MAX_LENGTH		=> 3*2**16,
};

use constant ALL_FLAGS	=>
    UNENCRYPTED_FLAG	|
    SINGLE_CONNECT_FLAG;

our @server_flow_class;
$server_flow_class[AUTHEN] = "WEC::TacacsPlus::Session::Server::Authenticate";
$server_flow_class[AUTHOR] = "WEC::TacacsPlus::Session::Server::Authorize";
$server_flow_class[ACCT]   = "WEC::TacacsPlus::Session::Server::Account";

our @client_flow_class;
$client_flow_class[AUTHEN] = "WEC::TacacsPlus::Session::Client::Authenticate";
$client_flow_class[AUTHOR] = "WEC::TacacsPlus::Session::Client::Authorize";
$client_flow_class[ACCT]   = "WEC::TacacsPlus::Session::Client::Account";

sub init_server {
    my $connection = shift;
    $connection->{in_want}	= PRE_RECORD;
    $connection->{in_process}	= \&session_header;
}

sub init_client {
    my $connection = shift;
    $connection->{in_want}	= PRE_RECORD;
    $connection->{in_process}	= \&session_header;
}

sub secret {
    my $connection = shift;
    return defined $connection->{secret} ? $connection->{secret} :
        $connection->{parent}->secret unless @_;
    my $old = defined $connection->{secret} ? $connection->{secret} :
        $connection->{parent}->secret;
    $connection->{secret} = shift;
    return $old;
}

sub pseudo_pad {
    my ($header, $length, $secret) = @_;
    return "" unless $length >= 1;
    my $prefix = substr($header, 4, 4) . $secret .
        substr($header, 0, 1) . substr($header, 2, 1);
    my $pseudo_pad = my $last = md5($prefix);
    $pseudo_pad .= $last = md5($prefix . $last) for 1..($length-1)/16;
    return substr($pseudo_pad, 0, $length);
}

sub session_header {
    my $connection = shift;

    $connection->{header} = substr($_, 0, $connection->{in_want}, "");
    (my $major, $connection->{in_want}) =
        unpack("Cx7N", $connection->{header});
    $major >>= 4;
    if ($major != VERSION) {
        $connection->broken("TACACS+ packet with major version $major (I only speak ${\VERSION})");
        return;
    }
    if ($connection->{in_want} > MAX_LENGTH) {
        $connection->broken("TACACS+ packets can't be $connection->{in_want} bytes long");
        return;
    }
    $connection->{in_process}  = \&session_body;
}

sub session_body {
    my $connection = shift;

    my ($minor, $type, $seq_no, $flags, $session_id) =
        unpack("CCCCa4", $connection->{header});
    $minor &= 0x0f;

    my WEC::TacacsPlus::Session $session;
    eval {
        # Sanity checks, maybe move some tests to head
        ($flags & ~ALL_FLAGS) == 0 ||
            die sprintf("TACACS+ packet with unknown flags 0x%02x\n",
                        $flags & ~ALL_FLAGS);
        if ($connection->{direction} == SERVER) {
            if ($seq_no == 1) {
                $session = $connection->new_flow
                    ($server_flow_class[$type] || croak("Unknown session type $type"),
                     $connection->{options}, $session_id);
            } elsif ($seq_no % 2 == 0) {
                die "TACACS+ server received an even numbered packet\n";
            } else {
                $session = $connection->{flows}{$session_id} ||
                    die("TACACS+ packet for non-existent session " .
                        unpack("N", $session_id) . "\n");
                $session->isa($server_flow_class[$type] || die "Unknown session type $type\n") || die("TACACS+ packet tries to use a ", ref($session), " session as a $server_flow_class[$type]\n");
            }
        } elsif ($connection->{direction} != CLIENT) {
            die "Assertion failed: Active TACACS+ connection is neither server not client\n";
        } elsif ($seq_no % 2) {
            die "TACACS+ client received an odd numbered packet\n";
        } else {
            $session = $connection->{flows}{$session_id} ||
                die("TACACS+ packet for non-existent session " .
                    unpack("N", $session_id) . "\n");
            $session->isa($client_flow_class[$type] || die "Unknown session type $type\n") || die("TACACS+ packet tries to use a ", ref($session), " session as a $client_flow_class[$type]\n");
        }
        ++$session->{seq_no} == $seq_no ||
            die "TACACS+ packet with non-consecutive sequence number\n";
    };
    if ($@) {
        my $err = $@;
        $err =~ s/\n\z//;
        $connection->broken($err);
        return;
    }
    my $want = $connection->{in_want};
    $connection->{in_want}	= PRE_RECORD;
    $connection->{in_process}	= \&session_header;
    if (!defined $connection->{peer_mpx}) {
        $connection->{peer_mpx}	= $flags & SINGLE_CONNECT_FLAG ? 1 : 0;
        $connection->{flows_left} = 1 if
            !defined($connection->{flows_left}) && !$connection->{peer_mpx};
    }

    if ($want == 0) {
        # Empty body is a special kind of error message from the peer
        $session->_drop;
        return;
    }
    eval {
        if ($flags & UNENCRYPTED_FLAG) {
            $session->got(substr($_, 0, $want, "") . "", $minor);
        } else {
            my $secret = $connection->secret;
            if (!defined($secret)) {
                $connection->broken("Encrypted TACACS+ packet, but I have no secret");
                return;
            }
            $session->got(substr($_, 0, $want, "") ^
                          pseudo_pad($connection->{header}, $want, $secret),
                          $minor);
        }
    };
    return unless $@;
    my $err = $@;
    $session->_drop if $session->{parent};
    die $err;
}

# Call as $conn->send($session, $minor, $type, $content)
sub send : method {
    my $connection = shift;
    die "Attempt to send on a closed Connection" unless
        $connection->{out_handle};
    my WEC::TacacsPlus::Session $session = shift;
    die "Message is utf8" if utf8::is_utf8($_[2]);
    my $length = length($_[2]);
    die "Message too long" if $length >= 2**32;
    if ($connection->{direction} == SERVER) {
        $session->{seq_no} % 2 == 1 || croak "Double send by TACACS+ server";
    } elsif ($connection->{direction} == CLIENT) {
        $session->{seq_no} % 2 == 0 || croak "Double send by TACACS+ client";
    } else {
        die "Assertion failed: Role is neither client nor server";
    }
    die "Sequence number $session->{seq_no} too high" if
        $session->{seq_no} >= 255;
    $connection->send0 if $connection->{out_buffer} eq "";
    $connection->{out_buffer} .= my $header =
        pack("CCCCa4N", VERSION << 4 | shift, shift,
             ++$session->{seq_no},
             ($session->{crypt} ? 0 : UNENCRYPTED_FLAG) |
             ($connection->{host_mpx} ? SINGLE_CONNECT_FLAG : 0),
             $session->{id}, $length);
    # print STDERR "length=", length($_[0]), ":", WEC::Connection::hex_show($_[0]), "\n";
    if ($session->{crypt}) {
        defined(my $secret = $connection->secret) ||
            croak "No secret to encrypt with";
        $connection->{out_buffer} .=
            shift ^ pseudo_pad($header, $length, $secret);
    } else {
        $connection->{out_buffer} .= shift;
    }
    return;
}

#sub _close {
#    warn("_close @_[1..$#_]\n");
#    shift->SUPER::_close(@_);
#}

# 1;
# __END__

sub session {
    my $connection = shift;

    $connection->{direction} == CLIENT || croak "Not a client connection";
    keys %{$connection->{flows}} < MAX_SESSIONS ||
        croak "Too many sessions";
    # Replace rand by something crypto good --Ton
    my $id;
    1 while $connection->{flows}{$id = pack("N", rand(2**32))};
    return $connection->new_flow
        ($client_flow_class[$_[0]] || croak("Unknown session type $_[0]"),
         $connection->{options}, $id, shift);
}

sub authenticate {
    my $session = shift->session(AUTHEN);
    eval { $session->_authenticate(@_) };
    return $session unless $@;
    my $err = $@;
    $session->_drop;
    die $err;
}

sub authorize {
    my $session = shift->session(AUTHOR);
    eval { $session->_authorize(@_) };
    return $session unless $@;
    my $err = $@;
    $session->_drop;
    die $err;
}

sub account {
    my $session = shift->session(ACCT);
    eval { $session->_account(@_) };
    return $session unless $@;
    my $err = $@;
    $session->_drop;
    die $err;
}

1;
