use 5.008_001;
use strict;
use warnings;
use Time::HiRes qw(time);

use WEC::Test(TraceLine => 0,
              Class => "WEC::TacacsPlus",
              Parts =>[qw(Session Connection Client Server)]);

sub bad_packet {
    my ($packet, $client_message, $server_message) = @_;
    $server_message ||= $client_message;

    # Test client sending packet
    make_pair([Connect => sub {
        is(++$hit, 1, "First event");
        my $c = shift;
        WEC::Connection::send($c, $packet);
        $c->close_on_empty;
    },
               Close => sub {
                   is(++$hit, 2, "Second event");
                   $client = "";
               }],
              [Close => sub {
                   is(++$hit, 3, "Third event");
                   $server = "";
                   unloop;
               }]);
    warn_loop;
    is($hit, 3, "All events ran");
    is(@warnings, 1, "A problem was seen");
    like($warnings[0], $client_message);
    check_fd();
    check_objects();

    # Test server sending packet
    make_pair([Close => sub {
        is(++$hit, 3, "Third event");
        $client = "";
        unloop;
    }],
              [Accept => sub {
                  is(++$hit, 1, "First event");
                  my $c = $_[1];
                  WEC::Connection::send($c, $packet);
                  $c->close_on_empty;
              },
               Close => sub {
                   is(++$hit, 2, "Second event");
                   $server = "";
               }]);
    warn_loop;
    is($hit, 3, "All events ran");
    is(@warnings, 1, "A problem was seen");
    like($warnings[0], $server_message);
    check_fd();
    check_objects();
}

sub test {
    my $type = shift;
    my @args = @_;
    # Send around an accounting message
    my $error;
    # my (undef, $filename, $line) = caller;
    # diag("$filename: $line");
    make_pair([Crypt	=> 0,
               Connect	=> sub {
                   is(++$hit, 1, "First event");
                   my $c = shift;
                   eval { $c->$type(%{shift @args}) };
                   $error = $@;
                   if ($@) {
                       if (ref($args[0]) eq "HASH") {
                           diag($@);
                           fail("Should not have errored");
                       } else {
                           like($@, shift(@args), "Right error");
                       }
                       $hit++;	# Replaces the Account callback
                       $server = "";
                   }
               },
               AuthenticateResult => sub {
                   is(++$hit, @args < 2 ? 4 : 3, "Fourth event");
                   my ($session, %args) = @_;
                   isa_ok($session, "WEC::TacacsPlus::Session::Client::Authenticate",
                          "First arg is session");
                   is_deeply(\%args, shift(@args) || {
                       Pass	=> 1,
                       Minor	=> 0,
                       Message	=> 'yYy',
                       Data	=> 'zZ',
                       Status	=> 'Pass',
                       Echo	=> 1,
                   }, "Got back all info");
                   return unless @args;
                   # Continue....
                   eval { $session->continue(%{shift @args}) };
                   $error = $@;
                   if ($@) {
                       if (ref($args[0]) eq "HASH") {
                           diag($@);
                           fail("Should not have errored");
                       } else {
                           like($@, shift(@args), "Right error");
                       }
                       $hit = 2;
                       $server = "";
                   }
               },
               AuthorizeResult => sub {
                   is(++$hit, 4, "Fourth event");
                   my ($session, %args) = @_;
                   isa_ok($session, "WEC::TacacsPlus::Session::Client::Authorize",
                          "First arg is session");
                   is_deeply(\%args, shift(@args) || {
                       PassAdd	=> 1,
                       Minor	=> 0,
                       Message	=> 'yYy',
                       Data	=> 'zZ',
                       Status	=> 'PassAdd',
                       Args	=> ["foo"],
                   }, "Got back all info");
               },
               AccountResult => sub {
                   is(++$hit, 4, "Fourth event");
                   my ($session, %args) = @_;
                   isa_ok($session, "WEC::TacacsPlus::Session::Client::Account",
                          "First arg is session");
                   is_deeply(\%args, shift(@args) || {
                       Success	=> 1,
                       Minor	=> 0,
                       Message	=> 'yYy',
                       Data	=> 'zZ',
                       Status	=> 'Success'
                       }, "Got back all info");
               },
               Close => sub {
                   $hit = 4 if $error;
                   is(++$hit, 5, "Fifth event");
                   $client = "";
                   unloop;
               }],
              [Crypt => 0,
               OneShot	=> 1,
               Authenticate => sub {
                   is(++$hit, 2, "Second event");
                   my ($session, %args) = @_;
                   isa_ok($session, "WEC::TacacsPlus::Session::Server::Authenticate",
                          "First arg is session");
                   is_deeply(\%args, shift(@args), "Got all args");
                   $session->reply(@args ? %{shift @args} :
                                   (Status	=> "pass",
                                    Message	=> "yYy",
                                    Data	=> "zZ"));
               },
               AuthenticateContinue => sub {
                   is(++$hit, 4, "Second event");
                   $hit = 2;
                   my ($session, %args) = @_;
                   isa_ok($session, "WEC::TacacsPlus::Session::Server::Authenticate",
                          "First arg is session");
                   is_deeply(\%args, shift(@args), "Got all args");
                   $session->reply(@args ? %{shift @args} :
                                   (Status	=> "pass",
                                    Message	=> "yYy",
                                    Data	=> "zZ"));
               },
               Authorize => sub {
                   is(++$hit, 2, "Second event");
                   my ($session, %args) = @_;
                   isa_ok($session, "WEC::TacacsPlus::Session::Server::Authorize",
                          "First arg is session");
                   is_deeply(\%args, shift(@args), "Got all args");
                   $session->reply(@args ? %{shift @args} :
                                   (Status	=> "pass add",
                                    Message	=> "yYy",
                                    Data	=> "zZ",
                                    Args	=> ["foo"]));
               },
               Account => sub {
                   is(++$hit, 2, "Second event");
                   my ($session, %args) = @_;
                   isa_ok($session, "WEC::TacacsPlus::Session::Server::Account",
                          "First arg is session");
                   is_deeply(\%args, shift(@args), "Got all args");
                   $session->reply(@args ? %{shift @args} :
                                   (Status => "success",
                                    Message =>"yYy", Data => "zZ"));
               },
               Close => sub {
                   is(++$hit, 3, "Third event");
                   $server = "";
               }]);
    loop;
    is($hit, 5, "Got all events");
    check_fd();
    check_objects();
}

WEC->init;
check_fd;

# Load client module
use_ok("WEC::TacacsPlus::Client");

# Load server module
use_ok("WEC::TacacsPlus::Server");

# Load constants module
use_ok("WEC::TacacsPlus::Constants", ":all");

check_objects;

check_fd;
check_objects;

for my $type qw(Unix Tcp) {
    $socket_type = $type;

    # Try to make a client
    $client = eval { WEC::TacacsPlus::Client->new };
    is($@, "", "Could create client");
    # Free client
    $client = undef;
    check_objects;

    # Try to make a server
    make_socket;
    WEC->init;
    $server = eval {
        WEC::TacacsPlus::Server->new
            (Handle => $socket,
             $socket_type eq "Unix" ? (Paths => $destination) : ()) };
    $socket = undef;
    is($@, "", "Could create server");
    # Free server
    $server = undef;
    check_objects;
    check_fd;

    # Make server and client connect
    make_socket();
    $server = WEC::TacacsPlus::Server->new
        (Handle => $socket,
         $socket_type eq "Unix" ? (Paths => $destination) : ());
    $socket = undef;
    $client = WEC::TacacsPlus::Client->new(Destination => $destination);
    my $c = $client->connect;
    isa_ok($c, "WEC::TacacsPlus::Connection", "Good type of connection");
    is($client->connections, 1, "One connection");
    my @conns = $client->connections;
    is(@conns, 1, "One connection");
    is($conns[0], $c, "Same connection we already knew");
    @conns = ();
    WEC->add_alarm(1, sub {
        is($server->connections, 1, "One connection");
        my @conns = $server->connections;
        is(@conns, 1, "One connection");
        isnt($conns[0], $c, "Server connection isn't client connection");
        $c = $server = $client = undef;
        @conns = ();
        unloop;
    });
    loop;
    check_fd();
    check_objects();

    my $connected = 0;
    # Connect and let server die
    make_pair([Connect => sub {
        is(++$connected, 1, "Got Connect");
        is(@_, 2, "Right number of arguments");
        my ($c, $dest) = @_;
        is($client->connections, 1, "Have one connection");
        my @conn = $client->connections;
        is(@conn, 1, "Have one connection");
        is($c, $conn[0], "Right incoming connection");
        is($dest, $destination, "Right destination");
        is($client->destination, $destination, "Destination call knows too");

        is($client->secret, undef, "Client secret unregistered");
        is($c->secret, undef, "Connection gets client secret");

    },
               Close => sub {
                   is(++$hit, 4, "Second event");
                   is(@_, 3, "Close gets three arguments");
                   is(shift, $client, "First is the client");
                   isa_ok(shift, "WEC::TacacsPlus::Connection", "second is a connection");
                   is(shift, "eof", "Reason is normal close");

                   # Check connection list
                   is($client->connections, 0, "Connection is gone by now");

                   is($client->destination, $destination, "Client knows where to go");

                   # Clean up client
                   $client = "";
                   unloop;
               }],
              [PreAccept => sub {
                  is(++$hit, 1, "First event");
                  is(@_, 1, "PreAccept gets one arguments");
                  is(shift, $server, "And it's the server");
              },
               Accept => sub {
                   is(++$hit, 2, "Second event");
                   is(@_, 2, "Accept gets two arguments");
                   is(shift, $server, "First one is the server");
                   my $c = shift;
                   isa_ok($c, "WEC::TacacsPlus::Connection",
                          "second is a connection");
                   my @conn = $server->connections;
                   is(@conn, 1, "Indeed only one connection");
                   is($c, $conn[0], "And this is it");

                   is($server->secret, undef, "Server secret unregistered");
                   is($c->secret, undef, "Connection gets server secret");

                   # Clean up server and by implication the connection
                   $server = "";
               },
               Close => sub {
                   is(++$hit, 3, "Third event");
                   is(@_, 3, "Close gets three arguments");
                   my $s = shift;
                   isa_ok($s, "WEC::TacacsPlus::Server",
                          "First is the server");
                   isa_ok(shift, "WEC::TacacsPlus::Connection",
                          "second is a connection");
                   is(shift, "abort", "Reason is abort");

                   # Check connection list
                   is($s->connections, 0, "Connection is gone by now");
               }]);
    loop;
    is($hit, 4, "All events ran");
    is($connected, 1, "All events ran");
    check_fd();
    check_objects();

    # Connect and let client die
    $connected = 0;
    make_pair([Secret => "bar",
               Connect => sub {
                   is(++$connected, 1, "Got connect");
                   my ($c, $dest) = @_;
                   isa_ok($c, "WEC::TacacsPlus::Connection");
                   is($dest, $destination, "Right destination");
                   is($client->destination, undef, "No default destination");
                   is($client->secret, "bar", "Client secret registered");
                   is($c->secret, "bar", "Connection knows client secret");
                   $client = "";
               },
               Close => sub {
                   is(++$connected, 2, "Second event");
                   is($_[2], "abort", "Reason is abort");
                   # Check connection list
                   is($_[0]->connections, 0, "Connection is gone by now");
               }],
              [Secret => "foo",
               Accept => sub {
                   is(++$hit, 1, "First event");
                   my $c = $_[1];
                   isa_ok($c, "WEC::TacacsPlus::Connection");
                   is($server->secret, "foo", "Server secret registered");
                   is($c->secret, "foo", "Connection knows server secret");
               },
               Close => sub {
                   is(++$hit, 2, "Second event");
                   is($_[2], "eof", "Reason is eof");
                   # Check connection list
                   is($_[0]->connections, 0, "Connection is gone by now");
                   $server = "";
                   unloop;
               }], 1);
    loop;
    is($hit, 2, "All events ran");
    is($connected, 2, "All events ran");
    check_fd();
    check_objects();

    bad_packet(pack("CCCCa4N", 0x10, 1, 1, 0, "1234", 0) =>
               qr/^Flow processor error \(closing connection\):.*major version 1 /i);
    bad_packet(pack("CCCCa4N", 0xc0, 1, 1, 0, "1234", 1e6) =>
               qr/^Flow processor error \(closing connection\):.*long/i);
    bad_packet(pack("CCCCa4N", 0xc0, 1, 1, 0xff, "1234", 0) =>
               qr/^Flow processor error \(closing connection\):.*unknown flags/i);
    bad_packet(pack("CCCCa4N", 0xc0, 1, 2, 0, "1234", 0) =>
               qr/^Flow processor error \(closing connection\):.*even number/i,
               qr/^Flow processor error \(closing connection\):.*non-existent session/i);
    bad_packet(pack("CCCCa4N", 0xc0, 1, 3, 0, "1234", 0) =>
               qr/^Flow processor error \(closing connection\):.*non-existent session/i,
               qr/^Flow processor error \(closing connection\):.*odd number/i);
    bad_packet(pack("CCCCa4N", 0xc0, 0xff, 1, 0, "1234", 0) =>
               qr/^Flow processor error \(closing connection\):.*Unknown session type 255/i,
               qr/^Flow processor error \(closing connection\):.*odd number/i);

    # We check basic roundtrips in the order account, authorize, authenticate
    # Which is from simple to complex (and the reverse order of the spec)
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "PPP",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"});
    test(authenticate => {
        Action		=> 0+AUTHEN_LOGIN(),
        Privilege	=> 0+PRIV_LVL_ROOT(),
        Type		=> 0+AUTHEN_TYPE_ARAP(),
        Service		=> 0+AUTHEN_SVC_PPP(),
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "PPP",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Minor		=> 15,
          Status	=> 255,
          Flags		=> 255,
          Message	=> "m" x (2**16-1),
          Data		=> "d" x (2**16-1)},
         {Minor		=> 15,
          Status	=> 255,
          Flags		=> 254,
          Echo		=> 0,
          Message	=> "m" x (2**16-1),
          Data		=> "d" x (2**16-1)});
    test(authenticate => {
        Action		=> "chpass",
        Privilege	=> "user",
        Type		=> "ascii",
        Service		=> "none",
        User		=> "",
        Port		=> "",
        RemoteAddress	=> "",
        Data		=> ""},
         {Minor		=> 0,
          Action	=> "ChangePassword",
          Privilege	=> "1",
          Type		=> "ASCII",
          Service	=> "None",
          User		=> "",
          Port		=> "",
          RemoteAddress	=> "",
          Data		=> ""},
         {Minor		=> 8,
          Status	=> "fail",
          Echo		=> 1,
          Message	=> "",
          Data		=> ""},
         {Minor		=> 8,
          Status	=> "Fail",
          Fail		=> 1,
          Echo		=> 1,
          Message	=> "",
          Data		=> ""});
    test(authenticate => {
        Action		=> "sendpass",
        Privilege	=> "max",
        Type		=> "arap",
        Service		=> "login",
        Port		=> "baR",
        RemoteAddress	=> "baz"},
         {Minor		=> 1,
          Action	=> "SendPassword",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "Login",
          User		=> "",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> ""},
         {Status	=> "fail",
          Echo		=> 2,
          Message	=> undef,
          Data		=> undef},
         {Minor		=> 0,
          Status	=> "Fail",
          Fail		=> 1,
          Echo		=> 1,
          Message	=> "",
          Data		=> ""});
    test(authenticate => {
        Action		=> "sendpass",
        Privilege	=> "max",
        Type		=> "arap",
        Service		=> "login",
        Port		=> "baR",
        RemoteAddress	=> "baz"},
         {Minor		=> 1,
          Action	=> "SendPassword",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "Login",
          User		=> "",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> ""},
         {Status	=> "restart",
          Echo		=> 2,
          Message	=> undef,
          Data		=> undef},
         {Minor		=> 0,
          Status	=> "Restart",
          Restart	=> 1,
          Echo		=> 1,
          Message	=> "",
          Data		=> {}});
    test(authenticate => {
        Action		=> "sendpass",
        Privilege	=> "max",
        Type		=> "arap",
        Service		=> "login",
        Port		=> "baR",
        RemoteAddress	=> "baz"},
         {Minor		=> 1,
          Action	=> "SendPassword",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "Login",
          User		=> "",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> ""},
         {Status	=> "restart",
          Echo		=> 2,
          Message	=> undef,
          Data		=> "abc"},
         {Minor		=> 0,
          Status	=> "Restart",
          Restart	=> 1,
          Echo		=> 1,
          Message	=> "",
          Data		=> {
              ord("a") => 1,
              ord("b") => 1,
              ord("c") => 1,
          }});
    test(authenticate => {
        Action		=> "sendpass",
        Privilege	=> "max",
        Type		=> "arap",
        Service		=> "login",
        Port		=> "baR",
        RemoteAddress	=> "baz"},
         {Minor		=> 1,
          Action	=> "SendPassword",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "Login",
          User		=> "",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> ""},
         {Status	=> "restart",
          Echo		=> 2,
          Message	=> undef,
          Data		=> [0+AUTHEN_TYPE_ARAP(), qw(ASCII PAP)]},
         {Minor		=> 0,
          Status	=> "Restart",
          Restart	=> 1,
          Echo		=> 1,
          Message	=> "",
          Data		=> {
              ASCII	=> 1,
              ARAP	=> 1,
              PAP	=> 1,
          }});
    test(authenticate => {
        Action		=> "sendpass",
        Privilege	=> "max",
        Type		=> "arap",
        Service		=> "login",
        Port		=> "baR",
        RemoteAddress	=> "baz"},
         {Minor		=> 1,
          Action	=> "SendPassword",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "Login",
          User		=> "",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> ""},
         {Status	=> "restart",
          Echo		=> 2,
          Message	=> undef,
          Data		=> {0+AUTHEN_TYPE_ARAP() => 1, ASCII => 2, PAP => 1, CHAP => 0, MSCHAP => undef}},
         {Minor		=> 0,
          Status	=> "Restart",
          Restart	=> 1,
          Echo		=> 1,
          Message	=> "",
          Data		=> {
              ASCII	=> 1,
              ARAP	=> 1,
              PAP	=> 1,
          }});
    test(authenticate => {
        Action		=> "sendpass",
        Privilege	=> "max",
        Type		=> "arap",
        Service		=> "login",
        Port		=> "baR",
        RemoteAddress	=> "baz"},
         {Minor		=> 1,
          Action	=> "SendPassword",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "Login",
          User		=> "",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> ""},
         {Status	=> "restart",
          Echo		=> 2,
          Message	=> undef,
          Data		=> {256 => 1}},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Type 256 is too big"});
    test(authenticate => {
        Action		=> "sendpass",
        Privilege	=> "max",
        Type		=> "arap",
        Service		=> "login",
        Port		=> "baR",
        RemoteAddress	=> "baz"},
         {Minor		=> 1,
          Action	=> "SendPassword",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "Login",
          User		=> "",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> ""},
         {Status	=> "restart",
          Echo		=> 2,
          Message	=> undef,
          Data		=> [256]},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Type 256 is too big"});
    test(authenticate => {
        Action		=> "sendpass",
        Privilege	=> "max",
        Type		=> "arap",
        Service		=> "login",
        Port		=> "baR",
        RemoteAddress	=> "baz"},
         {Minor		=> 1,
          Action	=> "SendPassword",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "Login",
          User		=> "",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> ""},
         {Status	=> "restart",
          Echo		=> 2,
          Message	=> undef,
          Data		=> {woo => 1}},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Unknown authentication type 'woo'"});
    test(authenticate => {
        Action		=> "sendpass",
        Privilege	=> "max",
        Type		=> "arap",
        Service		=> "login",
        Port		=> "baR",
        RemoteAddress	=> "baz"},
         {Minor		=> 1,
          Action	=> "SendPassword",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "Login",
          User		=> "",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> ""},
         {Status	=> "restart",
          Echo		=> 2,
          Message	=> undef,
          Data		=> ["woo"]},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Unknown authentication type 'woo'"});
    test(authenticate => {
        Action		=> "sendauth",
        Privilege	=> "min",
        Type		=> "chap",
        Service		=> "ppp",
        User		=> undef,
        Port		=> undef,
        RemoteAddress	=> undef,
        Data		=> undef},
         {Minor		=> 1,
          Action	=> "SendAuthentication",
          Privilege	=> "0",
          Type		=> "CHAP",
          Service	=> "PPP",
          User		=> "",
          Port		=> "",
          RemoteAddress	=> "",
          Data		=> ""},
         {Status	=> "error",
          Echo		=> 0},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 0,
          Message	=> "",
          Data		=> ""});
    test(authenticate => {
        Action		=> "enable",
        Privilege	=> "root",
        Type		=> "mschap",
        Service		=> "enable",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "MSCHAP",
          Service	=> "Enable",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "follow",
          Echo		=> undef,
          Message	=> "yYy",
          Data		=> "zZ"},
         {Minor		=> 0,
          Status	=> "Follow",
          Follow	=> 1,
          Echo		=> 0,
          Message	=> "yYy",
          Data		=> [{Host => "zZ"}]});
    test(authenticate => {
        Action		=> "enable",
        Privilege	=> "root",
        Type		=> "arap",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "Enable",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> 256,
          Message	=> "yYy",
          Data		=> "zZ"},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Status 256 is too big"});
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "enable",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "Enable",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "fail",
          Message	=> "y" x 2**16,
          Data		=> "zZ"},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Message field too long"});
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "arap",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "ARAP",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "fail",
          Message	=> "yYy",
          Data		=> "z" x 2**16},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Data field too long"});
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "pt",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "PT",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "fail",
          Flags		=> 256,
          Message	=> "yYy",
          Data		=> "zZ"},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Flags 256 is too big"});
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "rcmd",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "Rcmd",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Minor		=> 16,
          Status	=> "fail",
          Message	=> "yYy",
          Data		=> "zZ"},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Minor '16' is too big (max 4 bits)"});
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "x25",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "X25",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Minor		=> "z",
          Status	=> "fail",
          Message	=> "yYy",
          Data		=> "zZ"},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Non numeric minor 'z'"});
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "nasi",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "NASI",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "wee",
          Message	=> "yYy",
          Data		=> "zZ"},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Unknown authentication status 'wee'"});
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "fwproxy",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "FwProxy",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "fail",
          Message	=> chr(256),
          Data		=> "zZ"},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Wide character in Message"});
    test(authenticate => {
        Minor		=> 15,
        Action		=> 255,
        Privilege	=> 15,
        Type		=> 255,
        Service		=> 255,
        User		=> "f" x 255,
        Port		=> "b" x 255,
        RemoteAddress	=> "z" x 255,
        Data		=> "w" x 255},
         {Minor		=> 15,
          Action	=> 255,
          Privilege	=> "15",
          Type		=> 255,
          Service	=> 255,
          User		=> "f" x 255,
          Port		=> "b" x 255,
          RemoteAddress	=> "z" x 255,
          Data		=> "w" x 255},
         {Status	=> "fail",
          Message	=> "yYy",
          Data		=> chr(256)},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Wide character in Data"});
    test(authenticate => {
        Minor		=> 15,
        Action		=> 255,
        Privilege	=> 15,
        Type		=> 255,
        Service		=> 255,
        User		=> "f" x 255,
        Port		=> "b" x 255,
        RemoteAddress	=> "z" x 255,
        Data		=> "w" x 255},
         {Minor		=> 15,
          Action	=> 255,
          Privilege	=> "15",
          Type		=> 255,
          Service	=> 255,
          User		=> "f" x 255,
          Port		=> "b" x 255,
          RemoteAddress	=> "z" x 255,
          Data		=> "w" x 255},
         {Status	=> "fail",
          Waffle	=> 26,
          Message	=> "yYy",
          Data		=> "d"},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Echo		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Unknown options Waffle"});

    # Continue packets
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "PPP",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "getdata",
          Message	=> "rRr",
          Data		=> "dd"},
         {Minor		=> 0,
          Status	=> "GetData",
          GetData	=> 1,
          Echo		=> 1,
          Message	=> "rRr",
          Data		=> "dd"},
         {Message	=> "me",
          Data		=> "weenie"},
         {Minor		=> 0,
          Message	=> "me",
          Data		=> "weenie"});
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "PPP",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "getuser",
          Message	=> "rRr",
          Data		=> "dd"},
         {Minor		=> 0,
          Status	=> "GetUser",
          GetUser	=> 1,
          Echo		=> 1,
          Message	=> "rRr",
          Data		=> "dd"},
         {Minor		=> 15,
          Flags		=> 254,
          Message	=> "m" x (2**16-1),
          Data		=> "w" x (2**16-1)},
         {Minor		=> 15,
          Flags		=> 254,
          Message	=> "m" x (2**16-1),
          Data		=> "w" x (2**16-1)});
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "PPP",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "getpass",
          Message	=> "rRr",
          Data		=> "dd"},
         {Minor		=> 0,
          Status	=> "GetPassword",
          GetPassword	=> 1,
          Echo		=> 0,
          Message	=> "rRr",
          Data		=> "dd"},
         {Minor		=> 16,
          Message	=> "me",
          Data		=> "weenie"},
         qr!Minor '16' is too big \(max 4 bits\) at t/TestKernel.pm!);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "PPP",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "getpass",
          Message	=> "rRr",
          Data		=> "dd"},
         {Minor		=> 0,
          Status	=> "GetPassword",
          GetPassword	=> 1,
          Echo		=> 0,
          Message	=> "rRr",
          Data		=> "dd"},
         {Minor		=> "me",
          Message	=> "me",
          Data		=> "weenie"},
         qr!Non numeric minor 'me' at t/TestKernel.pm!);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "PPP",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "getpass",
          Message	=> "rRr",
          Data		=> "dd"},
         {Minor		=> 0,
          Status	=> "GetPassword",
          GetPassword	=> 1,
          Echo		=> 0,
          Message	=> "rRr",
          Data		=> "dd"},
         {Message	=> "m" x 2**16,
          Data		=> "weenie"},
         qr!Message field too long at t/TestKernel.pm!);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "PPP",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "getpass",
          Message	=> "rRr",
          Data		=> "dd"},
         {Minor		=> 0,
          Status	=> "GetPassword",
          GetPassword	=> 1,
          Echo		=> 0,
          Message	=> "rRr",
          Data		=> "dd"},
         {Message	=> chr(256),
          Data		=> "weenie"},
         qr!Wide character in Message at t/TestKernel.pm!);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "PPP",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "getpass",
          Message	=> "rRr",
          Data		=> "dd"},
         {Minor		=> 0,
          Status	=> "GetPassword",
          GetPassword	=> 1,
          Echo		=> 0,
          Message	=> "rRr",
          Data		=> "dd"},
         {Message	=> "m",
          Data		=> "w" x 2**16},
         qr!Data field too long at t/TestKernel.pm!);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         {Minor		=> 1,
          Action	=> "Login",
          Privilege	=> "15",
          Type		=> "ARAP",
          Service	=> "PPP",
          User		=> "fOo",
          Port		=> "baR",
          RemoteAddress	=> "baz",
          Data		=> "woef"},
         {Status	=> "getpass",
          Message	=> "rRr",
          Data		=> "dd"},
         {Minor		=> 0,
          Status	=> "GetPassword",
          GetPassword	=> 1,
          Echo		=> 0,
          Message	=> "rRr",
          Data		=> "dd"},
         {Message	=> "m",
          Data		=> chr(256)},
         qr!Wide character in Data at t/TestKernel.pm!);

    # Failure modes
    test(authenticate => {
        Minor		=> 16,
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!Minor '16' is too big \(max 4 bits\) at t/TestKernel.pm!i);
    test(authenticate => {
        Minor		=> "z",
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!Non numeric minor 'z' at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "dogin",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!Unknown authentication action 'dogin' at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> 256,
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!Action 256 is too big at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> 16,
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!Invalid privilege level '16' at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "boot",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!Invalid privilege level 'boot' at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "trap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!Unknown authentication type 'trap' at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> 256,
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!Type 256 is too big at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "tpp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!Unknown authentication service 'tpp' at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> 256,
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!Service 256 is too big at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "f" x 256,
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!User field too long at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "foo",
        Port		=> "b" x 256,
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!Port field too long at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "foo",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!No Port specified at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "foo",
        Port		=> "bar",
        RemoteAddress	=> "b" x 256,
        Data		=> "woef"},
         qr!RemoteAddress field too long at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "foo",
        Port		=> "bar",
        Data		=> "woef"},
         qr!No RemoteAddress specified at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "foo",
        Port		=> "bar",
        RemoteAddress	=> "baz",
        Data		=> "w" x 256},
         qr!Data field too long at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> chr(256),
        Port		=> "bar",
        RemoteAddress	=> "baz",
        Data		=> "zoef"},
         qr!Wide character in User at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "foo",
        Port		=> chr(256),
        RemoteAddress	=> "baz",
        Data		=> "bar"},
         qr!Wide character in Port at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "foo",
        Port		=> "bar",
        RemoteAddress	=> chr 256,
        Data		=> "baz"},
         qr!Wide character in RemoteAddress at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "login",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "foo",
        Port		=> "bar",
        RemoteAddress	=> "baz",
        Data		=> chr 256},
         qr!Wide character in Data at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "enable",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!Service 3 \(PPP\) should be 'Enable' or undef if Action is 'Enable' at t/TestKernel.pm!i);
    test(authenticate => {
        Action		=> "chpass",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "enable",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress	=> "baz",
        Data		=> "woef"},
         qr!Service may not be 'Enable' for non login action 2 \(ChangePassword\) at t/TestKernel.pm!i);

    # Test accounting
    # Event variations
    test(account => {
        Event		=> "stop",
        Method		=> "tacacs+",
        Privilege	=> "root",
        Type		=> "arap",
        Service		=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'TACACS+',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type		=> 'ARAP',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']});
    test(account => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type		=> "arap",
        Service	=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         qr!No event specified.*t/TestKernel!i);
    test(account => {
        Event		=> "Flop",
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type		=> "arap",
        Service	=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         qr!Unknown accounting event 'flop'.*t/TestKernel!i);
    test(account => {
        Event		=> 0+ACCT_FLAG_STOP(),
        Method	=> "notset",
        Privilege	=> "user",
        Type		=> "arap",
        Service	=> "none",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> []},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'NotSet',
          Privilege	=> 1,
          Service	=> 'None',
          Type		=> 'ARAP',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> []},
         {Status => "error",
          Message =>"yYy", Data => "zZ"},
         {Minor		=> 0,
          Status 	=> "Error",
          Error		=> 1,
          Message	=> "yYy",
          Data		=> "zZ"
          });
    test(account => {
        Event		=> 256,
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type		=> "arap",
        Service	=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         qr!Event 256 is too big.*t/TestKernel!);
    test(account => {
        Event		=> "watchdog|start",
        Method	=> "none",
        Privilege	=> "min",
        Type		=> "arap",
        Service	=> "login",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 10,
          StartEvent	=> 1,
          WatchdogEvent	=> 1,
          Method	=> 'None',
          Privilege	=> 0,
          Service	=> 'Login',
          Type		=> 'ARAP',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=>"yYy",
          Data		=> "zZ"},
         {Minor		=> 0,
          Status	=> "Follow",
          Message	=> "yYy",
          Follow	=> 1,
          Data		=> [{
              Host	=> "zZ",
          }]});
    test(account => {
        Event		=> 251,
        Method	=> "kerberosv5",
        Privilege	=> "max",
        Type		=> "arap",
        Service	=> "enable",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 251,
          ExtraFlags	=> 240,
          StartEvent	=> 1,
          WatchdogEvent	=> 1,
          MoreEvent	=> 1,
          Method	=> 'KerberosV5',
          Privilege	=> 15,
          Service	=> 'Enable',
          Type		=> 'ARAP',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=>"Wat",
          Data		=> {Host => "dim"}},
         {Minor		=> 0,
          Status	=> "Follow",
          Message	=> "Wat",
          Follow	=> 1,
          Data		=> [{
              Host	=> "dim",
          }]});

    # Method variations
    test(account => {
        Event		=> "moRe",
        Privilege	=> 9,
        Type		=> "arap",
        Service	=> "arap",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 1,
          MoreEvent	=> 1,
          Method	=> 'NotSet',
          Privilege	=> 9,
          Service	=> 'ARAP',
          Type		=> 'ARAP',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Data => [{Host => "dom"},
                   {Protocol => 0+AUTHEN_METH_TACACSPLUS(),
                    Host => "dada"},
                   {Protocol => "krb5",
                    Host	=> "Woo",
                    Key => "keybe"},
                   {Host => "Zap",
                    Key => "grmbl"}]},
         {Minor		=> 0,
          Status	=> "Follow",
          Message	=> "",
          Follow	=> 1,
          Data		=> [{
              Host	=> "dom",
          },{
              Protocol => "TACACS+",
              Host => "dada",
          },{
              Protocol => "KerberosV5",
              Host	=> "Woo",
              Key => "keybe",
          },{
              Host => "Zap",
              Key => "grmbl"}]});
    test(account => {
        Event		=> "START",
        Method	=> 0+AUTHEN_METH_TACACSPLUS(),
        Privilege	=> "root",
        Type		=> "arap",
        Service	=> "pt",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 2,
          StartEvent	=> 1,
          Method	=> 'TACACS+',
          Privilege	=> 15,
          Service	=> 'PT',
          Type		=> 'ARAP',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "Wot",
          Data		=> {host => "dom"}},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "No Host in follow data entry",
      });
    test(account => {
        Event		=> "stop",
        Method	=> "Zoem",
        Privilege	=> "root",
        Type		=> "arap",
        Service	=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         qr!Unknown authentication method 'Zoem' at t/TestKernel!i);
    test(account => {
        Event		=> "stop",
        Method	=> 256,
        Privilege	=> "root",
        Type		=> "arap",
        Service	=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         qr!Method 256 is too big at t/TestKernel!i);
    test(account => {
        Event		=> "watchdog",
        Method	=> 255,
        Privilege	=> "root",
        Type		=> "arap",
        Service	=> "rcmd",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 8,
          WatchdogEvent	=> 1,
          Method	=> 255,
          Privilege	=> 15,
          Service	=> 'Rcmd',
          Type		=> 'ARAP',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "Follow",
          Message	=> "Wot",
          Data		=> {Host => ""}},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Empty Host in follow data entry",
      });

    # Privilege variations
    test(account => {
        Event		=> "stop",
        Method	=> "lInE",
        Type		=> "arap",
        Service	=> "x25",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'Line',
          Privilege	=> 1,
          Service	=> 'X25',
          Type		=> 'ARAP',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "Follow",
          Message	=> "Wot",
          Data		=> {Host => "hos\@tie" }},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Invalid characters in follow Host",
      });
    test(account => {
        Event		=> "stop",
        Method	=> "tacacs+",
        Privilege	=> 16,
        Type		=> "arap",
        Service	=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         qr!Invalid privilege level '16' at t/TestKernel!i);
    test(account => {
        Event		=> "stop",
        Method	=> "ENABLE",
        Privilege	=> 15,
        Type		=> "arap",
        Service	=> "nasi",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'Enable',
          Privilege	=> 15,
          Service	=> 'NASI',
          Type		=> 'ARAP',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "Follow",
          Message	=> "Wot",
          Data		=> {Host => "hostie",
                            Extra => "Stuff"}},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Unknown key 'Extra' in follow data entry",
      });

    # Type variations
    test(account => {
        Event		=> "stop",
        Method	=> "local",
        Privilege	=> "root",
        Service	=> "fwproxy",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'Local',
          Privilege	=> 15,
          Service	=> 'FwProxy',
          Type		=> 'ASCII',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "Follow",
          Message	=> "Wot",
          Data		=> {Host => "hostie",
                            Key => "St\x0duff"}},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Invalid characters in follow Key",
      });
    test(account => {
        Event		=> "stop",
        Method	=> "guest",
        Privilege	=> "root",
        Type		=> 0+AUTHEN_TYPE_PAP(),
        Service	=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'Guest',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type		=> 'PAP',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "Follow",
          Message	=> "Wot",
          Data		=> {Host => "hostie",
                            Protocol => 256}},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Protocol 256 is too big",
      });
    test(account => {
        Event		=> "stop",
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type		=> 256,
        Service	=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         qr!Type 256 is too big at t/TestKernel!i);
    test(account => {
        Event		=> "stop",
        Method	=> "Radius",
        Privilege	=> "root",
        Type		=> 255,
        Service	=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'RADIUS',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type		=> 255,
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "Follow",
          Message	=> "Wot",
          Data		=> '@foo@host'},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Invalid follow data entry",
      });

    # Service variations
    test(account => {
        Event		=> "stop",
        Method	=> "kerberosv4",
        Privilege	=> "root",
        Type		=> "asCii",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'KerberosV4',
          Privilege	=> 15,
          Service	=> 'Login',
          Type		=> 'ASCII',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "Follow",
          Message	=> "W" x (2**16-1),
          Data		=> "hosti" . "\x0dhost" x (2**16/5-1)},
         {Minor		=> 0,
          Status	=> "Follow",
          Follow	=> 1,
          Message	=> "W" x (2**16-1),
          Data		=> [{ Host => "hosti" },
                            ({Host => "host"}) x (2**16/5-1)],
      });
    test(account => {
        Event		=> "stop",
        Privilege	=> "root",
        Type		=> 255,
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         qr!No service known for authentication type '255' at t/TestKernel!i);
    test(account => {
        Event		=> "stop",
        Method	=> "rcmd",
        Privilege	=> "root",
        Type		=> "asCii",
        Service	=> 0+AUTHEN_SVC_PPP(),
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'Rcmd',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type		=> 'ASCII',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "Follow",
          Message	=> "W" x 2**16,
          Data		=> "hosti" . "\x0dhost" x (2**16/5-1)},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Message field too long",
      });
    test(account => {
        Event		=> "stop",
        Privilege	=> "root",
        Type		=> "asCii",
        Service	=> 256,
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         qr!Service 256 is too big at t/TestKernel!i);
    test(account => {
        Event		=> "stop",
        Method	=> "not set",
        Privilege	=> "root",
        Type		=> "asCii",
        Service	=> 255,
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'NotSet',
          Privilege	=> 15,
          Service	=> 255,
          Type		=> 'ASCII',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "Follow",
          Message	=> "W" x (2**16-1),
          Data		=> "hosti0" . "\x0dhost" x (2**16/5-1)},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Data field too long",
      });
    test(account => {
        Event		=> "stop",
        Method	=> "not set",
        Privilege	=> "root",
        Type		=> "asCii",
        Service	=> 255,
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'NotSet',
          Privilege	=> 15,
          Service	=> 255,
          Type		=> 'ASCII',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "Follow",
          Message	=> chr(256),
          Data		=> "hh" },
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Wide character in Message",
      });
    test(account => {
        Event		=> "stop",
        Method	=> "not set",
        Privilege	=> "root",
        Type		=> "asCii",
        Service	=> 255,
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'NotSet',
          Privilege	=> 15,
          Service	=> 255,
          Type		=> 'ASCII',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "Follow",
          Message	=> "m",
          Data		=> chr(256) },
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Wide character in Data",
      });
    test(account => {
        Event		=> "stop",
        Method	=> "not set",
        Privilege	=> "root",
        Type		=> "asCii",
        Service	=> 255,
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'NotSet',
          Privilege	=> 15,
          Service	=> 255,
          Type		=> 'ASCII',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> ['zoo=5', 'zar=8']},
         {Status	=> "Follow",
          Message	=> "m",
          Data		=> { Host => chr(256) }},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "Wide character in Data",
      });

    # User too long
    test(account => {
        Event		=> "stop",
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type		=> "arap",
        Service	=> "ppp",
        User		=> "f" x 256,
        Port		=> "baR",
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         qr!User field too long at t/TestKernel!i);

    # Port too long
    test(account => {
        Event		=> "stop",
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type		=> "arap",
        Service	=> "ppp",
        User		=> "fOo",
        Port		=> "b" x 256,
        RemoteAddress => "baz",
        Args		=> [qw(zoo=5 zar=8)]},
         qr!Port field too long at t/TestKernel!i);

    # Remote Address too long
    test(account => {
        Event		=> "stop",
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type		=> "arap",
        Service	=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "b" x 256,
        Args		=> [qw(zoo=5 zar=8)]},
         qr!RemoteAddress field too long at t/TestKernel!i);

    # Too many arguments
    test(account => {
        Event		=> "stop",
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type		=> "arap",
        Service	=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baZ",
        Args		=> [("zoo") x 256]},
         qr!Too many \(256\) arguments at t/TestKernel!i);
    test(account => {
        Event		=> "stop",
        Method	=> "krb5",
        Privilege	=> "root",
        Type		=> "arap",
        Service	=> "ppp",
        User		=> "fOo",
        Port		=> "baR",
        RemoteAddress => "baz"},
         {Minor		=> 0,
          Flags		=> 4,
          StopEvent	=> 1,
          Method	=> 'KerberosV5',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type		=> 'ARAP',
          User		=> 'fOo',
          Port		=> 'baR',
          RemoteAddress => 'baz',
          Args		=> []},
         {Status	=> "Error",
          Message	=> "Wrong",
          Data		=> "Stuff"},
         {Minor		=> 0,
          Status	=> "Error",
          Error		=> 1,
          Message	=> "Wrong",
          Data		=> "Stuff",
      });
    # add wide char tests for account

    # Test authorization
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'TACACS+',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type	=> 'ARAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']});
    test(authorize => {
        Method	=> 0+AUTHEN_METH_TACACSPLUS(),
        Privilege	=> 0+PRIV_LVL_ROOT(),
        Type	=> 0+AUTHEN_TYPE_ARAP(),
        Service	=> 0+AUTHEN_SVC_PPP(),
        User	=> "zOo",
        Port	=> "bar",
        RemoteAddress => "baZ",
        Args	=> [qw(zoo=6 zat=7)]},
         {Minor	=> 0,
          Method	=> 'TACACS+',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type	=> 'ARAP',
          User	=> 'zOo',
          Port	=> 'bar',
          RemoteAddress => 'baZ',
          Args	=> ['zoo=6', 'zat=7']});
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "max",
        Type	=> "ascii",
        Service	=> "none",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'TACACS+',
          Privilege	=> 15,
          Service	=> 'None',
          Type	=> 'ASCII',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "pass repl",
          Message	=> "yYy",
          Data	=> "zZ",
          Args	=> ["foo"]},
         {Minor	=> 0,
          Status	=> "PassReplace",
          PassReplace	=> 1,
          Message	=> "yYy",
          Data	=> "zZ",
          Args	=> ["foo"]
          });
    test(authorize => {
        Method	=> "notset",
        Privilege	=> "min",
        Type	=> "pap",
        Service	=> "login",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> []},
         {Minor	=> 0,
          Method	=> 'NotSet',
          Privilege	=> 0,
          Service	=> 'Login',
          Type	=> 'PAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> []},
         {Status	=> "fail",
          Message	=> "yYy",
          Data	=> "zZ",
          Args	=> [qw(foo bar)]},
         {Minor	=> 0,
          Status	=> "Fail",
          Fail	=> 1,
          Message	=> "yYy",
          Data	=> "zZ",
          Args	=> [qw(foo bar)],
      });
    test(authorize => {
        Method	=> "none",
        Privilege	=> "user",
        Type	=> "chap",
        Service	=> "enable",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz"},
         {Minor	=> 0,
          Method	=> 'None',
          Privilege	=> 1,
          Service	=> 'Enable',
          Type	=> 'CHAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> []},
         {Status	=> "error",
          Message	=> "yYy",
          Data	=> "zZ",
          Args	=> ["foo"]},
         {Minor	=> 0,
          Status	=> "Error",
          Error	=> 1,
          Message	=> "yYy",
          Data	=> "zZ",
          Args	=> ["foo"],
      });
    test(authorize => {
        Method	=> "kerBerosv5",
        Type	=> "mschap",
        Service	=> "arap",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'KerberosV5',
          Privilege	=> 1,
          Service	=> 'ARAP',
          Type	=> 'MSCHAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "yYy",
          Data	=> "ZzZ",
          Args	=> ["foo"]},
         {Minor	=> 0,
          Status	=> "Follow",
          Follow	=> 1,
          Message	=> "yYy",
          Args	=> ["foo"],
          Data	=> [{
              Host	=> "ZzZ",
          }]});
    test(authorize => {
        Method	=> "Line",
        Privilege	=> 8,
        Type	=> 255,
        Service	=> "pT",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'Line',
          Privilege	=> 8,
          Service	=> 'PT',
          Type	=> '255',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "yYy",
          Data	=> {Host => "dim"}},
         {Minor	=> 0,
          Status	=> "Follow",
          Follow	=> 1,
          Message	=> "yYy",
          Args	=> [],
          Data	=> [{
              Host	=> "dim",
          }]});
    test(authorize => {
        Method	=> "enable",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "rcmd",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'Enable',
          Privilege	=> 15,
          Service	=> 'Rcmd',
          Type	=> 'ARAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "yYy",
          Args	=> [],
          Data => [{Host => "dom"},
                   {Protocol => 0+AUTHEN_METH_TACACSPLUS(),
                    Host => "dada"},
                   {Protocol => "krb5",
                    Host	=> "Woo",
                    Key => "keybe"},
                   {Host => "Zap",
                    Key => "grmbl"}],
      },
         {Minor	=> 0,
          Status	=> "Follow",
          Follow	=> 1,
          Message	=> "yYy",
          Args	=> [],
          Data		=> [{
              Host	=> "dom",
          },{
              Protocol => "TACACS+",
              Host => "dada",
          },{
              Protocol => "KerberosV5",
              Host	=> "Woo",
              Key => "keybe",
          },{
              Host => "Zap",
              Key => "grmbl"}]});
    test(authorize => {
        Method	=> "local",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "x25",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'Local',
          Privilege	=> 15,
          Service	=> 'X25',
          Type	=> 'ARAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "yYy",
          Args	=> ["wooo"],
          Data	=> {host => "dom"}},
         {Minor	=> 0,
          Status	=> "Error",
          Error	=> 1,
          Message	=> "TACACS+ server internal error",
          Data		=> "No Host in follow data entry"});
    test(authorize => {
        Method	=> "guest",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "nasi",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'Guest',
          Privilege	=> 15,
          Service	=> 'NASI',
          Type	=> 'ARAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "yYy",
          Args	=> ["wooo"],
          Data	=> {Host => ""}},
         {Minor	=> 0,
          Status	=> "Error",
          Error	=> 1,
          Message	=> "TACACS+ server internal error",
          Data	=> "Empty Host in follow data entry"});
    test(authorize => {
        Method	=> "radius",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "fwProxy",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'RADIUS',
          Privilege	=> 15,
          Service	=> 'FwProxy',
          Type	=> 'ARAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "yYy",
          Args	=> ["wooo"],
          Data	=> {Host => "hos\@tie" }},
         {Minor	=> 0,
          Status	=> "Error",
          Error	=> 1,
          Message	=> "TACACS+ server internal error",
          Data	=> "Invalid characters in follow Host"});
    test(authorize => {
        Method	=> "KerberosV4",
        Privilege	=> "root",
        Type	=> "ascii",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'KerberosV4',
          Privilege	=> 15,
          Service	=> 'Login',
          Type	=> 'ASCII',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "yYy",
          Args	=> ["wooo"],
          Data	=> {Host => "hostie",
                    Extra => "Stuff"}},
         {Minor	=> 0,
          Status	=> "Error",
          Error	=> 1,
          Message	=> "TACACS+ server internal error",
          Data	=> "Unknown key 'Extra' in follow data entry"});
    test(authorize => {
        Method	=> "rcmd",
        Privilege	=> "root",
        Type	=> "pap",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'Rcmd',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type	=> 'PAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "yYy",
          Args	=> ["wooo"],
          Data		=> {Host => "hostie",
                            Key => "St\x0duff"}},
         {Minor	=> 0,
          Status	=> "Error",
          Error	=> 1,
          Message	=> "TACACS+ server internal error",
          Data	=> "Invalid characters in follow Key"});
    test(authorize => {
        Privilege	=> "root",
        Type	=> "chap",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'NotSet',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type	=> 'CHAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "yYy",
          Args	=> ["wooo"],
          Data	=> {Host => "hostie",
                    Protocol => 256}},
         {Minor	=> 0,
          Status	=> "Error",
          Error	=> 1,
          Message	=> "TACACS+ server internal error",
          Data	=> "Protocol 256 is too big"});
    test(authorize => {
        Method	=> 255,
        Privilege	=> "root",
        Type	=> "mschap",
        Port	=> "",
        RemoteAddress => "",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> '255',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type	=> 'MSCHAP',
          User	=> '',
          Port	=> '',
          RemoteAddress => '',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "yYy",
          Args	=> ["wooo"],
          Data	=> '@foo@host'},
         {Minor	=> 0,
          Status	=> "Error",
          Error	=> 1,
          Message	=> "TACACS+ server internal error",
          Data	=> "Invalid follow data entry"});
    test(authorize => {
        Method	=> 255,
        Privilege	=> "root",
        Type	=> "arap",
        User	=> "f" x 255,
        Port	=> "b" x 255,
        RemoteAddress => "z" x 255,
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> '255',
          Privilege	=> 15,
          Service	=> 'ARAP',
          Type	=> 'ARAP',
          User	=> "f" x 255,
          Port	=> "b" x 255,
          RemoteAddress => "z" x 255,
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "W" x (2**16-1),
          Args	=> ["wooo"],
          Data	=> "hosti" . "\x0dhost" x (2**16/5-1)},
         {Minor	=> 0,
          Status	=> "Follow",
          Follow	=> 1,
          Message	=> "W" x (2**16-1),
          Args	=> ["wooo"],
          Data	=> [{ Host => "hosti" },
                    ({Host => "host"}) x (2**16/5-1)],
      });
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'TACACS+',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type	=> 'ARAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "W" x 2**16,
          Args	=> ["wooo"],
          Data	=> "hosti" . "\x0dhost" x (2**16/5-1)},
         {Minor	=> 0,
          Status	=> "Error",
          Error	=> 1,
          Message	=> "TACACS+ server internal error",
          Data	=> "Message field too long",
      });
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'TACACS+',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type	=> 'ARAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "W" x (2**16-1),
          Args	=> ["wooo"],
          Data	=> "hosti0" . "\x0dhost" x (2**16/5-1)},
         {Minor	=> 0,
          Status	=> "Error",
          Error	=> 1,
          Args	=> [],
          Message	=> "TACACS+ server internal error",
          Data	=> "Data field too long",
      });
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'TACACS+',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type	=> 'ARAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "W",
          Args	=> ["wooo"],
          Data	=> chr(256) },
         {Minor	=> 0,
          Status	=> "Error",
          Error	=> 1,
          Args	=> [],
          Message	=> "TACACS+ server internal error",
          Data	=> "Wide character in Data",
      });
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         {Minor	=> 0,
          Method	=> 'TACACS+',
          Privilege	=> 15,
          Service	=> 'PPP',
          Type	=> 'ARAP',
          User	=> 'fOo',
          Port	=> 'baR',
          RemoteAddress => 'baz',
          Args	=> ['zoo=5', 'zar=8']},
         {Status	=> "follow",
          Message	=> "W",
          Args	=> ["wooo"],
          Data	=> { Host => chr(256) }},
         {Minor	=> 0,
          Status	=> "Error",
          Error	=> 1,
          Args	=> [],
          Message	=> "TACACS+ server internal error",
          Data	=> "Wide character in Data",
      });

    # Some errors
    test(authorize => {
        Method	=> 256,
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         qr!Method 256 is too big at.*.*t/TestKernel!i);
    test(authorize => {
        Method	=> -1,
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         qr!Unknown authentication method '-1' at.*.*t/TestKernel!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> 16,
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         qr!Invalid privilege level '16' at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> -1,
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         qr!Invalid privilege level '-1' at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> 256,
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         qr!Type 256 is too big at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> -1,
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         qr!Unknown authentication type '-1' at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> 256,
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         qr!ervice 256 is too big at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "zoem",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         qr!Unknown authentication service 'zoem' at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "f" x256,
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         qr!User field too long at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5)]},
         qr!No Port specified at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "b" x 256,
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         qr!Port field too long at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> chr(256),
        RemoteAddress => "baz",
        Args	=> [qw(zoo=5 zar=8)]},
         qr!Wide character in Port at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baz",
        Args	=> [qw(zoo=5)]},
         qr!No RemoteAddress specified at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "b" x 256,
        Args	=> [qw(zoo=5 zar=8)]},
         qr!RemoteAddress field too long at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => chr(256),
        Args	=> [qw(zoo=5 zar=8)]},
         qr!Wide character in RemoteAddress at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> ["z" x 256]},
         qr!Argument too long at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [chr(256)]},
         qr!Wide character in argument at t/TestKernel.pm!i);
    test(authorize => {
        Method	=> "tacacs+",
        Privilege	=> "root",
        Type	=> "arap",
        Service	=> "ppp",
        User	=> "fOo",
        Port	=> "baR",
        RemoteAddress => "baz",
        Args	=> [("zoo=5") x 256]},
         qr!Too many \(256\) arguments at t/TestKernel.pm!i);

    for my $secret (undef, "squeamish ossifrage") {
        my ($now, $end);
        $hit = 0;
        my %send_request =
            (Event	=> "stop",
             Method	=> "tacacs+",
             Privilege	=> "root",
             Type	=> "arap",
             Service	=> "ppp",
             User	=> "fOo",
             Port	=> "baR",
             RemoteAddress => "baz",
             Args	=> [qw(zoo=5 zar=8)]);
        make_pair([$secret ? (Secret => $secret) : (Crypt => 0),
                   Connect	=> sub {
                       # $now=1+int(time);
                       # 1 while $now > time;
                       $now = time();
                       $end = $now+1;
                       shift->account(%send_request);
                   },
                   AccountResult => sub {
                       $hit++;
                       if ($end >= time) {
                           shift->connection->account(%send_request);
                       } else {
                           my $ms = sprintf("%.1f", (time()-$now)*1000/$hit);
                           diag("$type: All on one connection (with" . ($secret ? "   " : "out") . " secret) roundtrip: $ms ms");
                           $client = "";
                       }
                   }],
                  [$secret ? (Secret => $secret) : (Crypt => 0),
                   Account => sub {
                       shift->reply(Status => "success",
                                    Message =>"yYy", Data => "zZ");
                   },
                   Close => sub {
                       $server = "";
                       unloop;
                   }]);
        loop;
        check_fd();
    }

    check_fd();
    check_objects();
}


1;
