# ServerTACACSPLUS.pm
#
# Object for receiving TACACS+ requests and satisfying them
# Incoming TACACS+ authentication requests are converted into 
# Radius requests. ASCII, PAP, CHAP and MSCHAP are supported.
# Incoming TACACS+ authorization requests are always approved,
# and any cisco-avpair reply items from the previous Radius Access-Accept are 
# used as authorization attribute-value pairs
# Incoming TACACS+ accounting requests are converted into Radius
# accounting requests.
#
# Based on draft-grant-tacacs-02.txt 
#
# Author: Mike McCauley ([EMAIL PROTECTED])
# Copyright (C) 2003 Open System Consultants
# $Id: ServerTACACSPLUS.pm,v 1.15 2003/12/03 22:03:42 mikem Exp mikem $

package Radius::ServerTACACSPLUS;
@ISA = qw(Radius::Configurable);
use Radius::Configurable;
use Radius::Context;
use Digest::MD5;
use Socket;
use strict;

# Version numbers
$Radius::ServerTACACSPLUS::TAC_PLUSMAJOR_VERSION          = 0xc;
$Radius::ServerTACACSPLUS::TAC_PLUS_MINOR_VERSION_DEFAULT = 0;
$Radius::ServerTACACSPLUS::TAC_PLUSMINOR_VERSION_ONE      = 1;

# Request types
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN                = 1;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHOR                = 2;
$Radius::ServerTACACSPLUS::TAC_PLUS_ACCT                  = 3;

# Flags
$Radius::ServerTACACSPLUS::TAC_PLUS_UNENCRYPTED_FLAG      = 0x01; # Not really used!
$Radius::ServerTACACSPLUS::TAC_PLUS_SINGLE_CONNECT_FLAG   = 0x04;

# Authentication Start actions
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_LOGIN          = 1;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_CHPASS         = 2;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SENDPASS       = 3;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SENDAUTH       = 4;

# Authentication Start privelege levels
$Radius::ServerTACACSPLUS::TAC_PLUS_PRIV_LVL_MAX          = 0x0f;
$Radius::ServerTACACSPLUS::TAC_PLUS_PRIV_LVL_ROOT         = 0x0f;
$Radius::ServerTACACSPLUS::TAC_PLUS_PRIV_LVL_USER         = 0x01;
$Radius::ServerTACACSPLUS::TAC_PLUS_PRIV_LVL_MIN          = 0x00;

# Authentication Start authentication types
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_TYPE_ASCII     = 1;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_TYPE_PAP       = 2;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_TYPE_CHAP      = 3;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_TYPE_ARAP      = 4;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_TYPE_MSCHAP    = 5;

# Authentication Start service types
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SVC_NONE       = 0;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SVC_LOGIN      = 1;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SVC_ENABLE     = 2;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SVC_PPP        = 3;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SVC_ARAP       = 4;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SVC_PT         = 5;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SVC_RCMD       = 6;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SVC_X25        = 7;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SVC_NASI       = 8;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SVC_FWPROXY    =  9;

# Authentication Start status types
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_PASS    = 1;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_FAIL    = 2;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_GETDATA = 3;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_GETUSER = 4;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_GETPASS = 5;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_RESTART = 6;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_ERROR   = 7;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_FOLLOW  = 0x21;

# Authentication Start flags
$Radius::ServerTACACSPLUS::TAC_PLUS_REPLY_FLAG_NOECHO     = 1;

# Above value is correct but code uses this one
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_FLAG_NOECHO    = 1;

# Authentication Continue flags
$Radius::ServerTACACSPLUS::TAC_PLUS_CONTINUE_FLAG_ABORT     = 0x01;

# Authorization RESPONSE status types
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHOR_STATUS_PASS_ADD   = 0x01;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHOR_STATUS_PASS_REPL  = 0x02;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHOR_STATUS_FAIL       = 0x10;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHOR_STATUS_ERROR      = 0x11;
$Radius::ServerTACACSPLUS::TAC_PLUS_AUTHOR_STATUS_FOLLOW     = 0x21;

# Accounting flags
$Radius::ServerTACACSPLUS::TAC_PLUS_ACCT_MORE                = 0x01;
$Radius::ServerTACACSPLUS::TAC_PLUS_ACCT_START               = 0x02;
$Radius::ServerTACACSPLUS::TAC_PLUS_ACCT_STOP                = 0x04;
$Radius::ServerTACACSPLUS::TAC_PLUS_ACCT_WATCHDOG            = 0x08;

# Accounting reply status
$Radius::ServerTACACSPLUS::TAC_PLUS_ACCT_STATUS_SUCCESS      = 0x01;
$Radius::ServerTACACSPLUS::TAC_PLUS_ACCT_STATUS_ERROR        = 0x02;
$Radius::ServerTACACSPLUS::TAC_PLUS_ACCT_STATUS_FOLLOW       = 0x21;

# Map between Tacacs+ service types and Radius Service-Type
%Radius::ServerTACACSPLUS::service_to_service_type =
    (
     $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SVC_LOGIN => 'Login-User',
     $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SVC_ENABLE => 'Administrative-User',
     $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_SVC_PPP => 'Framed-User',
     );

#####################################################################
# This hash describes all the standards types of keywords understood by this
# class. If a keyword is not present in ConfigKeywords for this
# class, or any of its superclasses, Configurable will call sub keyword
# to parse the keyword
# See Configurable.pm for the list of permitted keywordtype
%Radius::ServerTACACSPLUS::ConfigKeywords = 
    (
     'Port'                 => 'string',
     'BindAddress'          => 'string',
     'MaxBufferSize'        => 'integer',
     'Key'                  => 'string',
     'AuthorizationAdd'     => 'stringarray',
     'AuthorizationReplace' => 'stringarray',
     'AuthorizationTimeout' => 'integer',
     'AddToRequest'         => 'string',
     'CommandAuth'	    => 'stringarray',
     );


#####################################################################
# Constructs a new handler
sub new
{
    my ($class, $file, @args) = @_;

    my $self = $class->SUPER::new($file, @args);

    $self->log($main::LOG_WARNING, "No Key defined for $class at '$main::config_file' line $.")
	if !defined $self->{Key};

    # Create a TCP socket to listen on, register it with select
    # Set up the TCP listener
    my $proto = getprotobyname('tcp');
    my $port = Radius::Util::get_port($self->{Port});
    &main::log($main::LOG_DEBUG, "Creating TACACSPLUS port $self->{BindAddress}:$port");
    my $s = do { local *FH };
    socket($s, Socket::PF_INET, Socket::SOCK_STREAM, $proto)
	|| $self->log($main::LOG_ERR,  "Could not create Server TACACSPLUS socket: $!");
    binmode($s); # Make safe in UTF environments
    setsockopt($s, Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1);
    my $bind_address = &Radius::Util::format_special($self->{BindAddress});
    bind($s, scalar Socket::sockaddr_in($port, Socket::inet_aton($bind_address)))
	|| $self->log($main::LOG_ERR,  "Could not bind Server TACACSPLUS socket: $!");
    listen($s, Socket::SOMAXCONN)
	|| $self->log($main::LOG_ERR,  "Could not listen on Server TACACSPLUS socket: $!");
    &Radius::Select::add_file
	(fileno($s), 1, undef, undef, 
	 \&handle_listen_socket_read, $s, $self);
    
}


#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
# Do per-instance default initialization. This is called after
# construction is complete
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Port} = 49;
    $self->{MaxBufferSize} = 100000;
    $self->{BindAddress} = '0.0.0.0';
    $self->{AuthorizationTimeout} = 10; # seconds
}

#####################################################################
# This is called by Select::select whenever our listen socket
# becomes readable, which means someone is trying to connect to us
# We accept the new connection
sub handle_listen_socket_read
{
    my ($fileno, $listensocket, $self) = @_;

    # This could have been done with FileHandle, but this is much
    # more lightweight. It makes a reference to a TYPEGLOB
    # and Perl can use a typeglob ref as an IO handle
    my $newsocket = do { local *FH };
    
    if (!accept($newsocket, $listensocket))
    {
	$self->log($main::LOG_ERR,  "Could not accept on Tacacs listen socket: $!");
	return;
    }

    Radius::TacacsplusConnection->new
	($self, $newsocket,
	 MaxBufferSize        => $self->{MaxBufferSize},
	 Key                  => $self->{Key},
	 AuthorizationTimeout => $self->{AuthorizationTimeout},
	 AddToRequest         => $self->{AddToRequest},
	 Identifier           => $self->{Identifier});
}

#####################################################################
#####################################################################
#####################################################################
package Radius::TacacsplusConnection;

#####################################################################
sub new
{
    my ($class, $parent, $socket, %args) = @_;

    my $self = {%args};
    bless $self, $class;  


    $self->{parent} = $parent;
    $self->{socket} = $socket;

    $self->{peer} = getpeername($self->{socket})
	|| $parent->log($main::LOG_ERR,  "Could not get peer name on TacacsplusConnection socket: $!");
    if (length $self->{peer} != 16)
    {
	$parent->log($main::LOG_ERR,  "Strange TACACS peer socket address length");
	return;
    }
    my ($port, $peeraddr) = Socket::unpack_sockaddr_in($self->{peer});
    $self->{peerport} = $port;
    $self->{peeraddr} = Socket::inet_ntoa($peeraddr);

    $self->{inbuffer} = undef;
    $self->{outbuffer} = undef;
    
    $self->{Trace} = 0; # Default trace level

    $parent->log($main::LOG_DEBUG,  "New TacacsplusConnection created for $self->{peeraddr}:$self->{peerport}");

    &Radius::Select::add_file
	(fileno($self->{socket}), 1, undef, undef, 
	 \&handle_connection_socket_read, $self);
}

#####################################################################
# Called when more data can be read from the socket
sub handle_connection_socket_read
{
    my ($fileno, $self) = @_;

    # Append the next lot of bytes to the buffer
    if (sysread($self->{socket}, $self->{inbuffer}, 16384, length $self->{inbuffer}))
    {
	if (length $self->{inbuffer} >= 12)
	{
	    # Have the header at least
	    my ($version, $type, $seq_no, $flags, $session_id, $length) 
		= unpack('CCCCNN', $self->{inbuffer});
	    # Make some trivial checks on the request
	    if ($version != 0xc0 &&$version != 0xc1)
	    {
		# REVISIT: should send an ERROR message
		$self->{parent}->log($main::LOG_ERR, "TacacsplusConnection received a request for unsupported version $version. Disconnecting");
		
		$self->disconnect();
	    }
	    if ($length > $self->{MaxBufferSize})
	    {
		$self->{parent}->log($main::LOG_ERR, "TacacsplusConnection received a request with excessive length $length. Disconnecting");
		$self->disconnect();
	    }
	    
	    if (length $self->{inbuffer} >= $length + 12)
	    {
		# Have the entire request
		# Get, clear and handle this request
		my $request = substr($self->{inbuffer}, 0, $length+12, undef);
		$self->request($request);
	    }
	}
    }
    else
    {
	# Strange, nothing there, must be a disconnection error
	$self->disconnect();
    }
}

#####################################################################
# Called when more data can be written to the socket
sub handle_connection_socket_write
{
    my ($fileno, $self) = @_;

    $self->write_pending();
    # Dont need this callback any more if all the pending bytes
    # have been written
    &Radius::Select::remove_file
	(fileno($self->{socket}), undef, 1, undef)
	    if !length $self->{outbuffer};
}

#####################################################################
# Called when a complete request has been received
# Parse and process it
# Version has been checked
sub request
{
    my ($self, $request) = @_;

    my ($version, $type, $seq_no, $flags, $session_id, $length, $body) 
	= unpack('CCCCNNa*', $request);

    $self->{parent}->log($main::LOG_DEBUG, "TacacsplusConnection request $version, $type, $seq_no, $flags, $session_id, $length");
    # Need these during the reply phase
    $self->{version} = $version;
    $self->{last_seq_no} = $seq_no;
    $self->{session_id} = $session_id;

    # Maybe decrypt the payload
    $body = &crypt($session_id, $self->{Key}, $version, $seq_no, $body) if defined($self->{Key});

    my $x = unpack('H*', $body);

    if ($type == $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN && $seq_no == 1)
    {
	$self->authentication_start($body);
    }
    elsif ($type == $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN)
    {
	$self->authentication_continue($body);
    }
    elsif ($type == $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHOR)
    {
	$self->authorization_request($body);
    }
    elsif ($type == $Radius::ServerTACACSPLUS::TAC_PLUS_ACCT)
    {
	$self->accounting_request($body);
    }
    # REVISIT: reset, error, etc
    else
    {
	$self->{parent}->log($main::LOG_WARNING, "TacacsplusConnection cant handle request type $type");
    }
}

#####################################################################
# Reversible TACACS+ encryption
sub crypt
{
    my ($session_id, $key, $version, $seq_no, $body) = @_;

    my ($res, $pad, $i);


    while ($i < length $body)
    {
	$pad = Digest::MD5::md5(pack('Na*CCa*', $session_id, $key, $version, $seq_no, $pad));
	$res .= substr($body, $i, 16) ^ $pad;
	$i += 16;
    }

    # Spec calls for encrypted data to be truncated to the length of
    # the cleartext message.
    $res = substr($res, 0, length($body));

    return $res;
}

#####################################################################
# Handle a TACACS+ authentication START request
sub authentication_start
{
    my ($self, $body) = @_;

    $self->{user} = undef;
    $self->{password} = undef;

    my ($action, $priv_lvl, $authen_type, $service, 
	$user_len, $port_len, $rem_addr_len, $data_len, 
	$fields) = unpack('CCCCCCCCa*', $body);
    # Decode the variable length fields
    my $i = 0;
    my $user     = substr($fields, $i, $user_len);     $i += $user_len;
    my $port     = substr($fields, $i, $port_len);     $i += $port_len;
    my $rem_addr = substr($fields, $i, $rem_addr_len); $i += $rem_addr_len;
    my $data     = substr($fields, $i, $data_len);     $i += $data_len;

    $self->{parent}->log($main::LOG_DEBUG, "TacacsplusConnection Authentication START $action, $authen_type, $service for $user, $port, $rem_addr");

    $self->{user} = $user;
    $self->{port} = $port;
    $self->{service} = $service;
    $self->{rem_addr} = $rem_addr;
    my $tp = $self->create_radius_request('Access-Request');

    if ($action == $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_LOGIN
	&& $authen_type == $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_TYPE_ASCII)
    {
	# Start of an ASCII login
	$self->{user} = $user;

	if (!length $user)
	{
	    $self->authentication_reply($Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_GETUSER,
					0,
					'Username: ');
	}
	else
	{
	    # Ask for the password
	    $self->authentication_reply($Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_GETPASS, $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_FLAG_NOECHO, 'Password: ');
	}
	# We should get an authentication CONTINUE soon.
	return;
	
    }
    elsif ($action == $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_LOGIN
	&& $authen_type == $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_TYPE_PAP)
    {
	# PAP login
	$tp->add_attr('User-Name', $user);
	$tp->add_attr('User-Password', $data);
	$tp->{DecodedPassword} = $data;
    }
    elsif ($action == $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_LOGIN
	&& $authen_type == $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_TYPE_CHAP)
    {
	# CHAP Login
	my ($chapid, $challenge, $result) = unpack('Ca16a16', $data);
	$tp->add_attr('User-Name', $user);
	$tp->add_attr('CHAP-Password', pack('Ca*', $chapid, $result));
	$tp->add_attr('CHAP-Challenge', $challenge);
    }
    else
    {
	$self->{parent}->log($main::LOG_WARNING, "TacacsplusConnection cant handle authentication action $action, type $authen_type");
	return;
    }

    $self->dispatch_radius_request($tp);
}

#####################################################################
# Create a standard fake Radius request
sub create_radius_request
{
    my ($self, $code) = @_;

    # Create a fake incoming radius request
    my $tp = Radius::Radius->new($main::dictionary);
    $tp->set_code($code);
    $tp->{RecvFrom} = $self->{peer};
    my @l = Socket::unpack_sockaddr_in($self->{peer});
    $tp->{RecvFromPort} = $l[0];
    $tp->{RecvFromAddress} = $l[1];
    $tp->{RecvTime} = time;
    $tp->{Client} = $self; # So you can use Client-Identifier check items
    $tp->set_authenticator(&Radius::Util::random_string(16));
    $tp->add_attr('NAS-IP-Address', $self->{peeraddr});
    $tp->add_attr('NAS-Port-Id', $self->{port}) if length $self->{port};
    $tp->add_attr('Calling-Station-Id', $self->{rem_addr}) if length $self->{rem_addr};
    $tp->add_attr('Service-Type', $Radius::ServerTACACSPLUS::service_to_service_type{$self->{service}}) if defined $Radius::ServerTACACSPLUS::service_to_service_type{$self->{service}};
    $tp->add_attr('Timestamp', time) if $code eq 'Accounting-Request';

    # Add arbitrary data to every request
    $tp->parse(&Radius::Util::format_special($self->{AddToRequest}))
	if (defined $self->{AddToRequest});

    # Arrange to call our reply function when we get a reply
    $tp->{replyFn} = [\&Radius::TacacsplusConnection::replyFn, $self];

    return $tp;
}

#####################################################################
# Dispatch a fake Radius request to the appropriate Handler
sub dispatch_radius_request
{
    my ($self, $tp) = @_;

    # Dump the fake radius request
    &main::log($main::LOG_DEBUG, "TACACSPLUS derived Radius request packet dump:\n" . $tp->dump)
	if (&main::willLog($main::LOG_DEBUG, $self->{parent}));

    # Now arrange for this fake radius request to be handled and find out the result
    my $originalname = $tp->get_attr('User-Name');
    $tp->{OriginalUserName} = $originalname;
    my ($userName, $realmName) = split(/@/, $originalname);
    my ($handler, $finder, $handled);
    foreach $finder (@Radius::Client::handlerFindFn)
    {
	if ($handler = &$finder($tp, $userName, $realmName))
	{
	    # Make sure the handler is updated with stats
	    push(@{$tp->{StatsTrail}}, \%{$handler->{Statistics}});
	    
	    # replyFn will be called from inside the handler when the
	    # reply is available
	    $handled = $handler->handle_request($tp);
	    last;
	}
    }
    $self->{parent}->log($main::LOG_WARNING, "TacacsplusConnection could not find a Handler")
	if !$handler;
}

#####################################################################
# Handle a TACACS+ authentication CONTINUE request
sub authentication_continue
{
    my ($self, $body) = @_;

    my ($user_msg_len, $data_len, $flags, $fields) = unpack('nnCa*', $body);
    # Decode the variable length fields
    my $i = 0;
    my $user_msg  = substr($fields, $i, $user_msg_len); $i += $user_msg_len;
    my $data      = substr($fields, $i, $data_len);     $i += $data_len;
    
    $self->{parent}->log($main::LOG_DEBUG, "TacacsplusConnection Authentication CONTINUE $flags, $user_msg, $data");

    if ($flags & $Radius::ServerTACACSPLUS::TAC_PLUS_CONTINUE_FLAG_ABORT)
    {
	$self->{parent}->log($main::LOG_WARN, "TacacsplusConnection Authentication CONTINUE aborted: $data");
	$self->disconnect();
    }

    if ($self->{last_status} == $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_GETPASS)
    {
	$self->{password} = $user_msg;
    }
    elsif ($self->{last_status} == $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_GETUSER)
    {
	$self->{user} = $user_msg;
    }
    if (   defined $self->{password}
	&& length $self->{user})
    {
	# Create and dispatch a fake radius request. When the result becomes available
	# our replyFn will be called
	my $tp = $self->create_radius_request('Access-Request');
	$tp->add_attr('User-Name', $self->{user});
	$tp->add_attr('User-Password', $self->{password});
	$tp->{DecodedPassword} = $self->{password};
	$self->dispatch_radius_request($tp);
    }
    else
    {
	# Need more data
	return $self->authentication_reply($Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_GETPASS,
					   $Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_FLAG_NOECHO,
					   'Password: ')
	    unless defined $self->{password};
	return $self->authentication_reply($Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_GETUSER,
					   0,
					   'Username: ')
	    unless length $self->{user};
    }
}

#####################################################################
sub authorization_request
{
    my ($self, $body) = @_;

    my ($authen_method, $priv_lvl, $authen_type, $authen_service, 
	$user_len, $port_len, $rem_addr_len, $arg_cnt, $fields) = unpack('CCCCCCCCa*', $body);
    my @arg_len = unpack("C$arg_cnt", substr($fields, 0, $arg_cnt, undef));
    # Decode the variable length fields
    my $i = 0;
    my $user     = substr($fields, $i, $user_len);     $i += $user_len;
    my $port     = substr($fields, $i, $port_len);     $i += $port_len;
    my $rem_addr = substr($fields, $i, $rem_addr_len); $i += $rem_addr_len;
    # Unpack additional args
    my (@args, $j);
    for ($j = 0; $j < @arg_len; $j++)
    {
	$args[$j] = substr($fields, $i, $arg_len[$j]);     $i += $arg_len[$j];
	$args[$j] =~ s/\0+$//;  # Strip trailing NULs that some clients add
    }

    $self->{parent}->log($main::LOG_DEBUG, "TacacsplusConnection Authorization REQUEST $authen_method, $priv_lvl, $authen_type, $authen_service, $user, $port, $rem_addr, $arg_cnt, @args");

    # Routers want different kinds of responses for command authorization,
    # just a pass or fail with NO extra attributes sent with the response.
    # 
    # Cisco is nice and just sets the authen_method to NONE instead of 
    # TACPLUS, but the Juniper E-series sends it as TACPLUS.  Only other 
    # way to identify is that both send command authorization requests 
    # with a 'cmd=' value and a 'cmg-arg=' value (even if the command 
    # entered has simply <cr> as an argument.) 
    #
    # The draft mentions nothing about using NONE for command auth, so we'll
    # proceed with the cmd/cmg-arg pair to identify it.
    #
    # - Paul Schultz 10/07/03 

    my $cmd_auth = 1 if $args[1] =~ /^cmd\=/ && $args[2] =~ /^cmd-arg\=/;

    my ($cmd_auth_response, $cmd_auth_reason) = command_authorization($self, $user, @args) if $cmd_auth == 1 && defined $self->{parent}->{CommandAuth};

    $self->{user} = $user;
    $self->{port} = $port;
    $self->{rem_addr} = $rem_addr;

    # Recover the context and any radius reply to our earlier authentication request
    my $context = &Radius::Context::find("tacacs:$self->{user}");
    my $rp = $context->{rp} if $context;
    my @reply_pairs = $rp->get_attr('cisco-avpair') if $rp;

    if ( $cmd_auth_response == 1 ) {
	$self->authorization_reply($Radius::ServerTACACSPLUS::TAC_PLUS_AUTHOR_STATUS_PASS_ADD);

    }
    elsif ( $cmd_auth_response == 2 ) {
	$self->authorization_reply($Radius::ServerTACACSPLUS::TAC_PLUS_AUTHOR_STATUS_FAIL, $cmd_auth_reason);
    }
    elsif (defined $self->{parent}->{AuthorizationReplace})
    {
	$self->authorization_reply($Radius::ServerTACACSPLUS::TAC_PLUS_AUTHOR_STATUS_PASS_REPL, 
				   undef, undef, 
				   @{$self->{parent}->{AuthorizationReplace}},
				   @{$self->{parent}->{AuthorizationAdd}},
				   @reply_pairs);
    }
    else
    {
	$self->authorization_reply($Radius::ServerTACACSPLUS::TAC_PLUS_AUTHOR_STATUS_PASS_ADD, 
				   undef, undef, 
				   @{$self->{parent}->{AuthorizationAdd}},
				   @reply_pairs);
    }
}


#####################################################################
# authorizes per-command for cisco routers 
sub command_authorization {

    my ($self, $user, @auth_args) = @_;
    my ($cmd_auth_response, $cmd_auth_reason);

    my $auth_service = shift(@auth_args);
    my $auth_cmd = shift(@auth_args);

    # just does a basic top-down search of CommandAuth attributes
    # to try to find a match.. first match wins.
    foreach my $command ( @{$self->{parent}->{CommandAuth}}  ) {

	my ($action,$command,$response) = split(' ', $command, 3);
	my @commands = split(":", $command);
	my $command_value = "cmd=" . shift(@commands);
	my $command_arg = "cmd-arg=" . shift(@commands);

	# match command by regex !! does NOT check arguments yet
	if ( $auth_cmd =~ /^$command_value$/ ) {

	    if ( $action eq "permit" ) {
		$cmd_auth_response = 1;
	    }
	    else { 
		$cmd_auth_response = 2; 
		$cmd_auth_reason = $response;
	    }
	    last;
	}
    }
    return ($cmd_auth_response, $cmd_auth_reason);
}


#####################################################################
sub accounting_request
{
    my ($self, $body) = @_;

    my ($flags, $authen_method, $priv_lvl, $authen_type, $authen_service, 
	$user_len, $port_len, $rem_addr_len, $arg_cnt, $fields) = unpack('CCCCCCCCCa*', $body);
    my @arg_len = unpack("C$arg_cnt", substr($fields, 0, $arg_cnt, undef));
    # Decode the variable length fields
    my $i = 0;
    my $user     = substr($fields, $i, $user_len);     $i += $user_len;
    my $port     = substr($fields, $i, $port_len);     $i += $port_len;
    my $rem_addr = substr($fields, $i, $rem_addr_len); $i += $rem_addr_len;
    # Unpack additional args
    my (@args, $j);
    for ($j = 0; $j < @arg_len; $j++)
    {
	$args[$j] = substr($fields, $i, $arg_len[$j]); $i += $arg_len[$j];
	$args[$j] =~ s/\0+$//;  # Strip trailing NULs that some clients add
    }

    $self->{parent}->log($main::LOG_DEBUG, "TacacsplusConnection Accounting REQUEST $flags, $authen_method, $priv_lvl, $authen_type, $authen_service, $user, $port, $rem_addr, $arg_cnt, @args");

    $self->{port} = $port;
    $self->{rem_addr} = $rem_addr;

    my $tp = $self->create_radius_request('Accounting-Request');
    $tp->add_attr('User-Name', $user);
    # REVISIT: May need to do something a bit more interesting with these AV pairs
    foreach (@args)
    {
	$tp->add_attr('cisco-avpair', $_);
    }
    $self->dispatch_radius_request($tp);
    $self->accounting_reply($Radius::ServerTACACSPLUS::TAC_PLUS_ACCT_STATUS_SUCCESS);
}

#####################################################################
# This function is called automatically when an authentication request
# has been serviced. $tp->{rp} will have been set to the reply message
sub replyFn
{
    my ($tp, $self) = @_;

    my $reply_code = $tp->{rp}->code();  # The result of the request
    $self->{parent}->log($main::LOG_DEBUG, "TacacsplusConnection result $reply_code");
    if ($reply_code eq 'Access-Accept')
    {
	$self->authentication_reply($Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_PASS, 0);

	# Sigh. Some TACACS clients (Cisco Aironet etc) create a new TCP session
	# for the authorisation phase. Therfore we cant cache the reply in $self.
	# So we have to create a context to hold the reply for a few seconds until
	# (maybe) an authorization REQUEST for this user arrives.
	my $context = Radius::Context->new("tacacs:$self->{user}", $self->{AuthorizationTimeout});
	$context->{rp} = $tp->{rp};
    }
    elsif ($reply_code eq 'Access-Reject')
    {
	$self->authentication_reply($Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN_STATUS_FAIL, 0);
    }
}

#####################################################################
# Assemble and send and authentication reply message
sub authentication_reply
{
    my ($self, $status, $flags, $server_msg, $data) = @_;

    $self->{parent}->log($main::LOG_DEBUG, "TacacsplusConnection Authentication REPLY $status, $flags, $server_msg, $data ");
    $self->{last_status} = $status;
    my $body = pack('CCnna*a*', $status, $flags, 
		   length($server_msg), length($data),
		   $server_msg, $data);
    $self->reply($Radius::ServerTACACSPLUS::TAC_PLUS_AUTHEN, $body);
}

#####################################################################
# Assemble and send and accounting reply message
sub accounting_reply
{
    my ($self, $status, $server_msg, $data) = @_;

    $self->{parent}->log($main::LOG_DEBUG, "TacacsplusConnection Accounting REPLY $status, $server_msg, $data ");
    my $body = pack('nnCa*a*',
		    length($server_msg), length($data),
		    $status,
		    $server_msg, $data);
    $self->reply($Radius::ServerTACACSPLUS::TAC_PLUS_ACCT, $body);
}

#####################################################################
# Assemble and send and authentication reply message
sub authorization_reply
{
    my ($self, $status, $server_msg, $data, @args) = @_;

    my $nargs = @args;
    my $arglenarray = pack('C*', map {length $_} @args);
    $self->{parent}->log($main::LOG_DEBUG, "TacacsplusConnection Authorization RESPONSE $status, $server_msg, $data, @args");
    my $body = pack("CCnna*a*a*a*", $status, $nargs,
		   length($server_msg), length($data), 
		    $arglenarray,
		   $server_msg, $data,
		    join('', @args));
    $self->reply($Radius::ServerTACACSPLUS::TAC_PLUS_AUTHOR, $body);
}

#####################################################################
# Assemble a complete TACACS+ message, and encrypt the body if required
sub reply
{
    my ($self, $type, $body) = @_;

    my $session_id = $self->{session_id};
    my $version = $self->{version};
    my $seq_no = $self->{last_seq_no} + 1;
    my $flags;

    # check if we're doing encryption
    if ( !defined($self->{Key}) )
    {
	$flags = $Radius::ServerTACACSPLUS::TAC_PLUS_UNENCRYPTED_FLAG;
    }

    $body = &crypt($session_id, $self->{Key}, $version, $seq_no, $body) if defined($self->{Key});
    
    my $msg = pack('CCCCNNa*', 
		   $version, 
		   $type,
		   $seq_no,
		   $flags,
		   $session_id,
		   length($body),
		   $body);
    $self->write($msg);
}

#####################################################################
sub write
{
    my ($self, $s) = @_;

    $self->{outbuffer} .= $s;
    if (length $self->{outbuffer} > $self->{MaxBufferSize})
    {
	$self->{parent}->log($main::LOG_ERR, "TacacsplusConnection MaxBufferSize exceeded, disconnecting");

	$self->disconnect();
    }
    else
    {
	$self->write_pending();
    }
}

#####################################################################
sub write_pending
{
    my ($self) = @_;

    # BUG ALERT what hapens if the syswrite blocks?
    my $written = syswrite($self->{socket}, $self->{outbuffer}, 
			   length $self->{outbuffer});
    if (!defined $written)
    {
	$self->{parent}->log($main::LOG_ERR, "TacacsplusConnection write error, disconnecting: $!");

	$self->disconnect();
    }
    else
    {
	# Remove the bytes that have been written already
	substr($self->{outbuffer}, 0, $written, '');

	# Anything left? it was a partial write, need to
	# get control when the socket is writeable again
	if (length $self->{outbuffer})
	{
	    &Radius::Select::add_file
		(fileno($self->{socket}), undef, 1, undef, 
		 \&handle_connection_socket_write, $self);
	}
    }
}

#####################################################################
sub disconnect
{
    my ($self) = @_;

    # Deleting any references to this TacacsConnection will
    # cause it to be destroyed    
    &Radius::Select::remove_file(fileno($self->{socket}), 1, 1, 1);

    $self->{parent}->log($main::LOG_DEBUG,  "TacacsplusConnection disconnected from $self->{peeraddr}:$self->{peerport}");
}

1;
