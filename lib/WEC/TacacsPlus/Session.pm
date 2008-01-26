package WEC::TacacsPlus::Session;
use 5.006;
use strict;
use warnings;
use Carp;

use WEC::TacacsPlus::Constants qw(:all);

our $VERSION = "0.01";
our @CARP_NOT = qw(WEC::TacacsPlus::Connection);

use base qw(WEC::Flow);
# use fields qw(seq_no crypt result);

our @EXPORT_OK = qw($server_error_message

                    @authen_action2name %authen_name2action %priv_level
                    %authen_type @authen_type2name %authen_type_minor
                    %authen_type_service @authen_service2name %authen_service
                    @authen_status2name %authen_name2status
                    @authen_method2name %authen_method

                    @author_status2name %author_name2status

                    %account_event @account_status2name @account_name2status);

our $server_error_message = "TACACS+ server internal error";

our @authen_action2name;
$authen_action2name[AUTHEN_LOGIN]	= "Login";
$authen_action2name[AUTHEN_CHPASS]	= "ChangePassword";
$authen_action2name[AUTHEN_SENDPASS]	= "SendPassword";
$authen_action2name[AUTHEN_SENDAUTH]	= "SendAuthentication";
our %authen_name2action =
    # Alternative names
    ("CHPASS"		=> AUTHEN_CHPASS,
     "CHANGEPASS"	=> AUTHEN_CHPASS,
     "CHANGE PASSWORD"	=> AUTHEN_CHPASS,
     "SENDPASS" 	=> AUTHEN_SENDPASS,
     "SEND PASSWORD" 	=> AUTHEN_SENDPASS,
     "SENDAUTH"		=> AUTHEN_SENDAUTH,
     "SEND AUTH"	=> AUTHEN_SENDAUTH);
$authen_name2action{uc($authen_action2name[$_] || next)} = $_
    for 0..$#authen_action2name;

our %priv_level =
    ("MAX"	=> PRIV_LVL_MAX,
     "ROOT"	=> PRIV_LVL_ROOT,
     "USER"	=> PRIV_LVL_USER,
     "MIN"	=> PRIV_LVL_MIN);
$priv_level{$_} = $_ for PRIV_LVL_MIN..PRIV_LVL_MAX;

our @authen_type2name;
$authen_type2name[AUTHEN_TYPE_ASCII]	= "ASCII";
$authen_type2name[AUTHEN_TYPE_PAP]	= "PAP";
$authen_type2name[AUTHEN_TYPE_CHAP]	= "CHAP";
$authen_type2name[AUTHEN_TYPE_ARAP]	= "ARAP";
$authen_type2name[AUTHEN_TYPE_MSCHAP]	= "MSCHAP";

our %authen_type;
$authen_type{uc($authen_type2name[$_] || next)} = $_ for 0..$#authen_type2name;

our %authen_type_minor =
    (AUTHEN_TYPE_PAP()		=> 1,
     AUTHEN_TYPE_CHAP()		=> 1,
     AUTHEN_TYPE_ARAP()		=> 1,
     AUTHEN_TYPE_MSCHAP()	=> 1);

our %authen_type_service =
    (AUTHEN_TYPE_ASCII()	=> AUTHEN_SVC_LOGIN,
     AUTHEN_TYPE_PAP()		=> AUTHEN_SVC_PPP,
     AUTHEN_TYPE_CHAP()		=> AUTHEN_SVC_PPP,
     AUTHEN_TYPE_MSCHAP()	=> AUTHEN_SVC_PPP,
     AUTHEN_TYPE_ARAP()		=> AUTHEN_SVC_ARAP);

our @authen_service2name;
$authen_service2name[AUTHEN_SVC_NONE]	= "None";
$authen_service2name[AUTHEN_SVC_LOGIN]	= "Login";
$authen_service2name[AUTHEN_SVC_ENABLE]	= "Enable";
$authen_service2name[AUTHEN_SVC_PPP]	= "PPP";
$authen_service2name[AUTHEN_SVC_ARAP]	= "ARAP";
$authen_service2name[AUTHEN_SVC_PT]	= "PT";
$authen_service2name[AUTHEN_SVC_RCMD]	= "Rcmd";
$authen_service2name[AUTHEN_SVC_X25]	= "X25";
$authen_service2name[AUTHEN_SVC_NASI]	= "NASI";
$authen_service2name[AUTHEN_SVC_FWPROXY]= "FwProxy";
our %authen_service;
$authen_service{uc($authen_service2name[$_] || next)} = $_ for
    0..$#authen_service2name;

our @authen_status2name;
$authen_status2name[AUTHEN_STATUS_PASS]		= "Pass";
$authen_status2name[AUTHEN_STATUS_FAIL]		= "Fail";
$authen_status2name[AUTHEN_STATUS_GETDATA]	= "GetData";
$authen_status2name[AUTHEN_STATUS_GETUSER]	= "GetUser";
$authen_status2name[AUTHEN_STATUS_GETPASS]	= "GetPassword";
$authen_status2name[AUTHEN_STATUS_RESTART]	= "Restart";
$authen_status2name[AUTHEN_STATUS_ERROR]	= "Error";
$authen_status2name[AUTHEN_STATUS_FOLLOW]	= "Follow";
our %authen_name2status =
    # Alternative names
    ("GET DATA"		=> AUTHEN_STATUS_GETDATA,
     "GET USER"		=> AUTHEN_STATUS_GETUSER,
     "GET PASSWORD"	=> AUTHEN_STATUS_GETPASS,
     "GETPASS"		=> AUTHEN_STATUS_GETPASS,
     "GET PASS"		=> AUTHEN_STATUS_GETPASS);
$authen_name2status{uc($authen_status2name[$_] || next)} = $_
    for 0..$#authen_status2name;

our @authen_method2name;
$authen_method2name[AUTHEN_METH_NOT_SET]	= "NotSet";
$authen_method2name[AUTHEN_METH_NONE]		= "None";
$authen_method2name[AUTHEN_METH_KRB5]		= "KerberosV5";
$authen_method2name[AUTHEN_METH_LINE]		= "Line";
$authen_method2name[AUTHEN_METH_ENABLE]		= "Enable";
$authen_method2name[AUTHEN_METH_LOCAL]		= "Local";
$authen_method2name[AUTHEN_METH_TACACSPLUS]	= "TACACS+";
$authen_method2name[AUTHEN_METH_GUEST]		= "Guest";
$authen_method2name[AUTHEN_METH_RADIUS]		= "RADIUS";
$authen_method2name[AUTHEN_METH_KRB4]		= "KerberosV4";
$authen_method2name[AUTHEN_METH_RCMD]		= "Rcmd";

our %authen_method =
    # Alternative names
    ("NOT SET"		=> AUTHEN_METH_NOT_SET,
     "KRB5"		=> AUTHEN_METH_KRB5,
     "KERBEROS5"	=> AUTHEN_METH_KRB5,
     "KERBEROS 5"	=> AUTHEN_METH_KRB5,
     "TACACSPLUS"	=> AUTHEN_METH_TACACSPLUS,
     "TACACS PLUS"	=> AUTHEN_METH_TACACSPLUS,
     "KRB4"		=> AUTHEN_METH_KRB4,
     "KERBEROS4"	=> AUTHEN_METH_KRB4,
     "KERBEROS 4"	=> AUTHEN_METH_KRB4);
$authen_method{uc($authen_method2name[$_] || next)} = $_
    for 0..$#authen_method2name;

our @author_status2name;
$author_status2name[AUTHOR_STATUS_PASS_ADD]	= "PassAdd";
$author_status2name[AUTHOR_STATUS_PASS_REPL]	= "PassReplace";
$author_status2name[AUTHOR_STATUS_FAIL]		= "Fail";
$author_status2name[AUTHOR_STATUS_ERROR]	= "Error";
$author_status2name[AUTHOR_STATUS_FOLLOW]	= "Follow";

our %author_name2status =
    # Alternative names
    ("PASS ADD"		=> AUTHOR_STATUS_PASS_ADD,
     "PASS REPLACE"	=> AUTHOR_STATUS_PASS_REPL,
     "PASSREPL"		=> AUTHOR_STATUS_PASS_REPL,
     "PASS REPL"	=> AUTHOR_STATUS_PASS_REPL);
$author_name2status{uc($author_status2name[$_] || next)} = $_
    for 0..$#author_status2name;

our %account_event =
    ("MORE"	=> ACCT_FLAG_MORE,
     "START"	=> ACCT_FLAG_START,
     "STOP"	=> ACCT_FLAG_STOP,
     "WATCHDOG"	=> ACCT_FLAG_WATCHDOG);

our @account_status2name;
$account_status2name[ACCT_STATUS_SUCCESS]	= "Success";
$account_status2name[ACCT_STATUS_ERROR]		= "Error";
$account_status2name[ACCT_STATUS_FOLLOW]	= "Follow";

our %account_name2status;
$account_name2status{uc($account_status2name[$_] || next)} = $_
    for 0..$#account_status2name;

my $follow_re =
    qr/(?:\@(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\@)?[^\@\x0d][^\x0d]*/;

sub init_flow {
    my $session = shift;
    $session->{parent} || croak "No parent object";
    $session->{options} = shift || croak "No options";
    defined($session->{id}   = shift) || croak "No id";
    $session->{seq_no}	= 0;
    $session->{crypt} = $session->{options}{Crypt};
    return $session->{id};
}

sub crypt : method {
    my $session = shift;
    return $session->{crypt} unless @_;
    my $old = $session->{crypt};
    $session->{crypt} = shift;
    return $old;
}

# 1;
# __END__

sub pack_follow {
    my $follow = shift;
    if (!ref($follow)) {
        $follow =~ /^$follow_re(?>\x0d$follow_re)*\z/ ||
            croak "Invalid follow data entry";
        return $follow;
    }
    my $data = "";
    $follow = [$follow] if ref($follow) eq "HASH";
    for (@$follow) {
        croak "No Host in follow data entry" unless exists $_->{Host};
        croak "Undefined Host in follow data entry" unless defined $_->{Host};
        croak "Empty Host in follow data entry" if $_->{Host} eq "";
        croak "Invalid characters in follow Host" if $_->{Host}=~/\@|\x0d/;
        my $keys = 1;

        if (exists $_->{Protocol}) {
            croak "Undefined Protocol in follow data entry" unless
                defined $_->{Protocol};
            if ($_->{Protocol} =~ /\A\d+\z/) {
                $_->{Protocol} < 256 ||
                    croak "Protocol $_->{Protocol} is too big";
                $data .= "\@$_->{Protocol}\@";
            } else {
                defined(my $m = $authen_method{uc($_->{Protocol})}) ||
                    croak "Unknown protocol '$_->{Protocol}'";
                $data .= "\@$m\@";
            }
            $keys++;
        }
        $data .= $_->{Host};
        if (exists $_->{Key}) {
            croak "Undefined Key in follow data entry" unless
                defined $_->{Key};
            croak "Invalid characters in follow Key" if $_->{Key}=~/\x0d/;
            $data .= "\@$_->{Key}";
            $keys++;
        }
        $data .= "\x0d";
        if ($keys != keys %$_) {
            my $keys = join ", " => map "'$_'", grep $_ ne "Host" && $_ ne "Protocol" && $_ ne "Key", keys %$_;
            croak "Unknown key $keys in follow data entry";
        }
    }
    chop $data;
    return $data;
}

sub unpack_follow {
    my @follow;
    for (split /\x0d/, shift, -1) {
        die "Empty follow entry\n" if $_ eq "";
        push @follow, \my %follow;
        if (/^\@/) {
            s/^\@(\d+)\@// || die "Bad protocol in follow entry\n";
            $follow{Protocol} = $authen_method2name[$1] || $1;
        }
        $follow{Key} = $1 if s/\@(.*)//s;
        die "Empty host in follow entry\n" if $_ eq "";
        $follow{Host} = $_;
    }
    die "No entries in follow data\n" unless @follow;
    return \@follow;
}

package WEC::TacacsPlus::Session::Server::Authenticate;
use Carp;
use WEC::TacacsPlus::Constants
    qw(AUTHEN CONTINUE_FLAG_ABORT AUTHEN_STATUS_FAIL REPLY_FLAG_NOECHO
       AUTHEN_STATUS_FOLLOW AUTHEN_STATUS_RESTART
       AUTHEN_STATUS_GETDATA AUTHEN_STATUS_GETUSER AUTHEN_STATUS_GETPASS);

our $VERSION = "0.01";
use base qw(WEC::TacacsPlus::Session);

our @CARP_NOT = qw(WEC::TacacsPlus::Connection);

sub pack_restart {
    my $types = shift;
    my $data = "";
    if (ref($types) eq "ARRAY") {
        for (@$types) {
            if (/\A\d+\z/) {
                $_ < 256 || croak "Type $_ is too big";
                $data .= pack("C", $_);
            } else {
                $data .= pack("C", $authen_type{uc($_)} ||
                              croak "Unknown authentication type '$_'");
            }
        }
        return $data;
    }
    if (ref($types) eq "HASH") {
        for (keys %$types) {
            next unless $types->{$_};
            if (/\A\d+\z/) {
                $_ < 256 || croak "Type $_ is too big";
                $data .= pack("C", $_);
            } else {
                $data .= pack("C", $authen_type{uc($_)} ||
                              croak "Unknown authentication type '$_'");
            }
        }
        return $data;
    }
    croak "Unknown restart type ", ref($types);
}

sub got {
    my $session = shift;
    my $seq_no = $session->{seq_no};
    die "Server authentication session received an invalid (even numbered) packet\n" if $seq_no % 2 == 0;
    # Odd numbered. Start or Continue
    if ($seq_no == 1) {
        # Start packet
        die "No authentication start handler\n" unless
            $session->{options}{Authenticate};
        die "Short authentication start packet\n" if length($_[0]) < 8;
        my ($action, $privilege, $type, $service, $user_len, $port_len,
            $rem_addr_len, $data_len) = unpack("C8", $_[0]);
        die "Bad authentication start packet length\n" if
            length($_[0]) !=
            8 + $user_len + $port_len + $rem_addr_len + $data_len;
        my ($user, $port, $rem_addr, $data) =
            unpack("x8a${user_len}a${port_len}a${rem_addr_len}a${data_len}", shift);
        $session->{options}{Authenticate}->
            ($session,
             Minor		=> shift,
             Action 	=> $authen_action2name[$action] || $action,
             Privilege 	=> $privilege,
             Type		=> $authen_type2name[$type] || $type,
             Service	=> $authen_service2name[$service] || $service,
             User		=> $user,
             Port		=> $port,
             RemoteAddress	=> $rem_addr,
             Data		=> $data);
        # Don't $session->_drop. The replying will do the drop if needed
    } else {
        # Continue packet
        die "No authentication continue handler\n" unless
            $session->{options}{AuthenticateContinue};
        die "Short authentication continue packet\n" if length($_[0]) < 5;
        my ($msg_len, $data_len) = unpack("nn", $_[0]);
        die "Bad authentication continue packet length\n" if
            length($_[0]) != 5 + $msg_len + $data_len;
        my ($flags, $message, $data) =
            unpack("x4Ca${msg_len}a${data_len}", shift);

        $session->{options}{AuthenticateContinue}->
            ($session, $flags & CONTINUE_FLAG_ABORT ?
             (Abort => 1,
              $flags & ~CONTINUE_FLAG_ABORT ?
              (Flags => $flags & ~CONTINUE_FLAG_ABORT) : ()) :
             $flags ? (Flags => $flags) : (),
             Minor	=> shift,
             Message=> $message,
             Data	=> $data);
        if ($flags & CONTINUE_FLAG_ABORT) {
            $session->_drop if $session->{parent};
            return;
        }
        # Don't $session->_drop. The replying will do the drop if needed
    }
    unless ($session->{seq_no} == $seq_no+1) {
        die "Weird jump in sequence number from $seq_no to $session->{seq_no}\n" if $session->{seq_no} != $seq_no;
        die "No authorization reply was sent\n" unless $session->{ended};
    }
}

sub reply {
    my ($session, %options) = @_;
    $session->{parent} ||
        croak "Cannot reply on a dropped authentication session";
    if ($session->{seq_no} %2 == 0) {
        # Triggerable by doing a reply that does not drop and then doing 
        # a reply again before receiving anything
        $session->_drop;
        croak "Unexpected sequence number $session->{seq_no}";
    }
    eval {
        defined(my $status = exists $options{Status} ?
                delete $options{Status} : AUTHEN_STATUS_FAIL) ||
                croak "No authentication reply status value";
        if ($status !~ /\A\d+\z/) {
            $status = $authen_name2status{uc($status)} ||
                croak "Unknown authentication status '$status'";
        }
        $status < 256 || croak "Status $status is too big";

        my $flags = delete $options{Flags};
        $flags = 0 unless defined($flags);
        $flags =~ /^\A\d+\z/ || croak "Flags is not an integer";
        if (exists $options{Echo}) {
            $flags |= delete $options{Echo} ? 0 : REPLY_FLAG_NOECHO;
        } elsif ($status == AUTHEN_STATUS_GETPASS) {
            $flags |= REPLY_FLAG_NOECHO;
        }
        $flags < 256 || croak "Flags $flags is too big";

        my $message = delete $options{Message};
        $message = "" unless defined($message);
        utf8::downgrade($message, 1) || croak "Wide character in Message";
        length($message) < 2**16 || croak "Message field too long";

        my $data = delete $options{Data};
        $data = "" unless defined($data);
        $data = WEC::TacacsPlus::Session::pack_follow($data) if $status == AUTHEN_STATUS_FOLLOW;
        $data = pack_restart($data) if
            $status == AUTHEN_STATUS_RESTART && ref($data);
        utf8::downgrade($data, 1) || croak "Wide character in Data";
        length($data) < 2**16 || croak "Data field too long";

        my $minor = delete $options{Minor};
        if (defined($minor)) {
            $minor =~ /\A\d+\z/ || croak "Non numeric minor '$minor'";
            $minor < 16 || croak "Minor '$minor' is too big (max 4 bits)";
        } else {
            $minor = 0;
        }

        croak "Unknown options ", join(", ", keys %options) if %options;

        $session->{parent}->send
            ($session, $minor, AUTHEN,
             pack("CCnna*a*", $status, $flags,
                  length($message), length($data), $message, $data));
        $session->_drop unless
            $status == AUTHEN_STATUS_GETDATA ||
            $status == AUTHEN_STATUS_GETUSER ||
            $status == AUTHEN_STATUS_GETPASS;
    };
    return unless $@;

    $@ =~ s/ at .* line \d+//g;
    $@ =~ s/\n\z//;
    # This leaks data to the clients. Probably should be configurable
    # Reply already does $session->_drop
    $session->reply(Status	=> "Error", 
                    Message => $server_error_message,
                    Data	=> $@);
    # die $@;
}

package WEC::TacacsPlus::Session::Client::Authenticate;
use Carp;
use WEC::TacacsPlus::Constants
    qw(AUTHEN AUTHEN_SVC_ENABLE AUTHEN_SVC_LOGIN AUTHEN_TYPE_ASCII
       REPLY_FLAG_NOECHO CONTINUE_FLAG_ABORT AUTHEN_LOGIN
       AUTHEN_STATUS_FOLLOW AUTHEN_STATUS_RESTART
       AUTHEN_STATUS_GETDATA AUTHEN_STATUS_GETUSER AUTHEN_STATUS_GETPASS);

our $VERSION = "0.01";
use base qw(WEC::TacacsPlus::Session);

our @CARP_NOT = qw(WEC::TacacsPlus::Connection);

# Maybe should return a list instead to preserve the order
sub unpack_restart {
    my %types;
    $types{$authen_type2name[$_] || $_} = 1 for unpack("C*", shift);
    return \%types;
}

sub _authenticate {
    my ($session, %options) = @_;
    croak "Not a virgin session" if $session->{seq_no};

    my $service = delete $options{Service};
    if (defined($service) && $service !~ /\A\d+\z/) {
        defined(my $s = $authen_service{uc($service)}) ||
            croak "Unknown authentication service '$service'";
        $service = $s;
    }

    defined(my $action = delete $options{Action}) ||
        croak "No Action specified";
    if ($action !~ /\A\d+\z/) {
        if ($action =~ /\AEnable\z/i) {
            croak "Service $service ", $authen_service2name[$service] ? "($authen_service2name[$service]) " : "", "should be 'Enable' or undef if Action is 'Enable'" if defined($service) && $service != AUTHEN_SVC_ENABLE;
            $service ||= AUTHEN_SVC_ENABLE;
            $action = AUTHEN_LOGIN;
        } else {
            $action = $authen_name2action{uc($action)} ||
                croak "Unknown authentication action '$action'";
        }
    }
    croak("Service may not be 'Enable' for non login action $action",
          $authen_action2name[$action] ? " ($authen_action2name[$action])":"")
        if defined($service) && $service == AUTHEN_SVC_ENABLE &&
        $action != AUTHEN_LOGIN;
   $action < 256 || croak "Action $action is too big";

    my $priv = delete $options{Privilege};
    $priv = "USER" unless defined($priv);
    defined(my $privilege = $priv_level{uc($priv)}) ||
        croak "Invalid privilege level '$priv'";

    my $type = delete $options{Type};
    if (!defined($type)) {
        $type = AUTHEN_TYPE_ASCII;
    } elsif ($type !~ /\A\d+\z/) {
        $type = $authen_type{uc($type)} ||
            croak "Unknown authentication type '$type'";
    }
    $type < 256 || croak "Type $type is too big";

    my $minor = delete $options{Minor};
    $minor = $authen_type_minor{$type} || 0 if !defined($minor);
    $minor =~ /\A\d+\z/ || croak "Non numeric minor '$minor'";
    $minor < 16 || croak "Minor '$minor' is too big (max 4 bits)";

    if (!defined($service)) {
        defined($service = $authen_type_service{$type}) ||
            croak "No service known for authentication type '$type'";
    }
    $service < 256 || croak "Service $service is too big";

    my $user = delete $options{User};
    $user = "" unless defined($user);
    utf8::downgrade($user, 1) || croak "Wide character in User";
    length($user) < 256 || croak "User field too long";

    exists $options{Port} || croak "No Port specified";
    my $port = delete $options{Port};
    $port = "" unless defined($port);
    utf8::downgrade($port, 1) || croak "Wide character in Port";
    length($port) < 256 || croak "Port field too long";

    exists $options{RemoteAddress} || croak "No RemoteAddress specified";
    my $rem_addr = delete $options{RemoteAddress};
    $rem_addr = "" unless defined($rem_addr);
    utf8::downgrade($rem_addr, 1) || croak "Wide character in RemoteAddress";
    length($rem_addr) < 256 || croak "RemoteAddress field too long";

    my $data = delete $options{Data};
    $data = "" unless defined($data);
    utf8::downgrade($data, 1) || croak "Wide character in Data";
    length($data) < 256 || croak "Data field too long";

    $session->{result} = delete $options{Result};

    croak "Unknown options ", join(", ", keys %options) if %options;

    $session->{parent}->send
        ($session, $minor, AUTHEN,
         pack("CCCCCCCCa*a*a*a*",
              $action, $privilege, $type, $service,
              length $user, length $port, length $rem_addr, length $data,
              $user, $port, $rem_addr, $data));
}

sub got {
    my $session = shift;
    my $seq_no = $session->{seq_no};
    die "Client authentication session received an invalid (odd numbered) packet\n" if $seq_no % 2;
    # Even numbered, must be a reply packet
    die "Short authentication reply packet\n" if
        length($_[0]) < 6;
    my ($status, $flags, $msg_len, $data_len) = unpack("CCnn", $_[0]);
    die "Bad authentication reply packet length\n" if
        length($_[0]) != $msg_len + $data_len + 6;
    my ($msg, $data) = unpack("x6a${msg_len}a${data_len}", shift);
    # print STDERR "status=$status,flags=$flags,msg='$msg',data='$data'\n";
    ($session->{result} || $session->{options}{AuthenticateResult} ||
     die "No 'AuthenticateResult' handler\n")->
     ($session,
      Minor	=> shift,
      Message => $msg,
      Data => $status == AUTHEN_STATUS_FOLLOW ? WEC::TacacsPlus::Session::unpack_follow($data) : $status == AUTHEN_STATUS_RESTART ? unpack_restart($data) : $data,
      $authen_status2name[$status] ?
      (Status => $authen_status2name[$status],
       $authen_status2name[$status] => 1) :
      # make copy so it can't be changed through @_
      (Status => 0+$status),
      Echo => $flags & REPLY_FLAG_NOECHO() ? 0 : 1,
      $flags & ~REPLY_FLAG_NOECHO() ?
      (Flags => $flags & ~REPLY_FLAG_NOECHO) : ());
    # Clean drop is allowed
    return unless $session->{parent};
    if ($status == AUTHEN_STATUS_GETDATA ||
        $status == AUTHEN_STATUS_GETUSER ||
        $status == AUTHEN_STATUS_GETPASS) {
        # Must be replied to

        # This kind of check isn't yet done for all got_
        # Maybe it shopuld be in Connection.pm anyways...
        unless ($session->{seq_no} == $seq_no+1) {
            die "Weird jump in sequence number from $seq_no to $session->{seq_no}\n" if $session->{seq_no} != $seq_no;
            die "No authentication continue was sent\n" unless $session->{ended};
        }
    } else {
        # Final packet
        $session->_drop;
    }
}

sub continue : method {
    my ($session, %options) = @_;
    eval {
        croak "A virgin session" unless $session->{seq_no};
        croak "Wrong parity sequence number. Double send ?" if
            $session->{seq_no} % 2;

        my $flags = delete $options{Flags};
        $flags = 0 unless defined($flags);
        if ($flags !~ /\A\d+\z/) {
            uc($flags) eq "ABORT" || croak "Unknown continue flags '$flags'";
            $flags = CONTINUE_FLAG_ABORT;
        }
        $flags |= CONTINUE_FLAG_ABORT if delete $options{Abort};
        $flags < 256 || croak "Flags $flags is too big";

        my $user_msg = delete $options{Message};
        if (!defined($user_msg)) {
            croak "No user message" unless $flags & CONTINUE_FLAG_ABORT;
            $user_msg = "";
        }
        utf8::downgrade($user_msg, 1) || croak "Wide character in Message";
        length($user_msg) < 2**16 || croak "Message field too long";

        my $data = delete $options{Data};
        $data = "" unless defined($data);
        utf8::downgrade($data, 1) || croak "Wide character in Data";
        length($data) < 2**16 || croak "Data field too long";

        my $minor = delete $options{Minor};
        if (defined($minor)) {
            $minor =~ /\A\d+\z/ || croak "Non numeric minor '$minor'";
            $minor < 16 || croak "Minor '$minor' is too big (max 4 bits)";
        } else {
            $minor = 0;
        }

        croak "Unknown options ", join(", ", keys %options) if %options;

        $session->{parent}->send
            ($session, $minor, AUTHEN,
             pack("nnCa*a*", length($user_msg), length($data), $flags,
                  $user_msg, $data));
    };
    return unless $@;
    my $err = $@;
    $session->_drop;
    die $err;
}

package WEC::TacacsPlus::Session::Server::Authorize;
use Carp;
use WEC::TacacsPlus::Constants
    qw(AUTHOR AUTHOR_STATUS_FAIL AUTHOR_STATUS_FOLLOW);

our $VERSION = "0.01";
use base qw(WEC::TacacsPlus::Session);

our @CARP_NOT = qw(WEC::TacacsPlus::Connection);

sub got {
    my $session = shift;
    die "Server authorization session received a packet with invalid sequence number $session->{seq_no}\n" if $session->{seq_no} != 1;
    # Number 1, must be an authorization request package
    die "No authorization request handler\n" unless
        $session->{options}{Authorize};
    my $left = length($_[0]) - 8;
    die "Short authorization request packet\n" if $left < 0;
    my ($user_len, $port_len, $rem_addr_len, $nr_args) =
        unpack('@4CCCC', $_[0]);
    my $read_args = 'CCCC@' . (8+$nr_args);
    $left -= $nr_args;
    $read_args .= "a$_", $left -=$_ for
        $user_len, $port_len, $rem_addr_len, unpack("\@8C$nr_args", $_[0]);
    die "Bad authorization request packet length\n" if $left;

    my ($method, $privilege, $type, $service, $user, $port, $rem_addr,
        @args) = unpack($read_args, shift);
    $session->{options}{Authorize}->
        ($session,
         Minor	=> shift,
         Method	=> $authen_method2name[ $method]  || $method,
         Privilege	=> $privilege,
         Type	=> $authen_type2name[   $type]	  || $type,
         Service	=> $authen_service2name[$service] || $service,
         User => $user, Port => $port, RemoteAddress => $rem_addr,
         Args => \@args);
    # Don't $session->_drop. The replying will do the drop
    return if $session->{seq_no} == 2;
    die "Weird jump in sequence number from 1 to $session->{seq_no}\n" if 
        $session->{seq_no} != 1;
    die "No authorization reply was sent\n" unless $session->{ended};
}

sub reply {
    my ($session, %options) = @_;
    $session->{parent} ||
        croak "Cannot reply on a dropped authorization session";
    # Should be impossible, since replying will drop the session
    croak "Assertion: Unexpected sequence number $session->{seq_no}" if
            $session->{seq_no} != 1;
    eval {
        defined(my $status = exists $options{Status} ?
                delete $options{Status} : AUTHOR_STATUS_FAIL) ||
                croak "No authorization reply status value";
        if ($status !~ /\A\d+\z/) {
            $status = $author_name2status{uc($status)} ||
                croak "Unknown authorization status '$status'";
        }
        $status < 256 || croak "Status $status is too big";

        my $message = delete $options{Message};
        $message = "" unless defined($message);
        utf8::downgrade($message, 1) || croak "Wide character in Message";
        length($message) < 2**16 || croak "Message field too long";

        my $data = delete $options{Data};
        $data = "" unless defined($data);
        $data = WEC::TacacsPlus::Session::pack_follow($data) if $status == AUTHOR_STATUS_FOLLOW;
        utf8::downgrade($data, 1) || croak "Wide character in Data";
        length($data) < 2**16 || croak "Data field too long";

        my $args = delete $options{Args};
        $args = [] unless defined($args);
        croak "Args is not an array reference" unless ref($args) eq "ARRAY";
        @$args < 256 || croak "Too many (", scalar @$args, ") arguments";
        my @args = @$args;
        utf8::downgrade($_, 1) || croak("Wide character in argument"),
        length() < 256 || croak "Argument too long" for @args;

        my $minor = delete $options{Minor};
        if (defined($minor)) {
            $minor =~ /\A\d+\z/ || croak "Non numeric minor '$minor'";
            $minor < 16 || croak "Minor '$minor' is too big (max 4 bits)";
        } else {
            $minor = 0;
        }

        croak "Unknown options ", join(", ", keys %options) if %options;

        $session->{parent}->send
            ($session, $minor, AUTHOR,
             pack("CCnnC" . @args . "(a*)*",
                  $status, scalar @args, length($message), length($data),
                  map(length, @args), $message, $data, @args));
        $session->_drop;
    };
    return unless $@;
    $@ =~ s/ at .* line \d+//g;
    $@ =~ s/\n\z//;
    # This leaks data to the clients. Probably should be configurable
    # Reply already does $session->_drop
    $session->reply(Status	=> "Error", 
                    Message => $server_error_message,
                    Data	=> $@);
    # die $@;
}

package WEC::TacacsPlus::Session::Client::Authorize;
use Carp;
use WEC::TacacsPlus::Constants
    qw(AUTHOR AUTHOR_STATUS_FOLLOW
       AUTHEN_METH_NOT_SET AUTHEN_TYPE_ASCII);

our $VERSION = "0.01";
use base qw(WEC::TacacsPlus::Session);

our @CARP_NOT = qw(WEC::TacacsPlus::Connection);

sub _authorize {
    my ($session, %options) = @_;
    croak "Not a virgin session" if $session->{seq_no};

    my $method = delete $options{Method};
    $method = AUTHEN_METH_NOT_SET unless defined($method);
    if ($method !~ /\A\d+\z/) {
        defined(my $m = $authen_method{uc($method)}) ||
                croak "Unknown authentication method '$method'";
        $method = $m;
    }
    $method < 256 || croak "Method $method is too big";

    my $priv = delete $options{Privilege};
    $priv = "USER" unless defined($priv);
    defined(my $privilege = $priv_level{uc($priv)}) ||
        croak "Invalid privilege level '$priv'";

    my $type = delete $options{Type};
    if (!defined($type)) {
        $type = AUTHEN_TYPE_ASCII;
    } elsif ($type !~ /\A\d+\z/) {
        $type = $authen_type{uc($type)} ||
            croak "Unknown authentication type '$type'";
    }
    $type < 256 || croak "Type $type is too big";

    my $service = delete $options{Service};
    if (!defined($service)) {
        defined($service = $authen_type_service{$type}) ||
            croak "No service known for authentication type '$type'";
    } elsif ($service !~ /\A\d+\z/) {
        defined(my $s = $authen_service{uc($service)}) ||
            croak "Unknown authentication service '$service'";
        $service = $s;
    }
    $service < 256 || croak "Service $service is too big";

    my $user = delete $options{User};
    $user = "" unless defined($user);
    utf8::downgrade($user, 1) || croak "Wide character in User";
    length($user) < 256 || croak "User field too long";

    exists $options{Port} || croak "No Port specified";
    my $port = delete $options{Port};
    $port = "" unless defined($port);
    utf8::downgrade($port, 1) || croak "Wide character in Port";
    length($port) < 256 || croak "Port field too long";

    exists $options{RemoteAddress} || croak "No RemoteAddress specified";
    my $rem_addr = delete $options{RemoteAddress};
    $rem_addr = "" unless defined($rem_addr);
    utf8::downgrade($rem_addr, 1) || croak "Wide character in RemoteAddress";
    length($rem_addr) < 256 || croak "RemoteAddress field too long";

    my $args = delete $options{Args};
    $args = [] unless defined($args);
    croak "Args is not an array reference" unless ref($args) eq "ARRAY";
    @$args < 256 || croak "Too many (", scalar @$args, ") arguments";
    my @args = @$args;
    utf8::downgrade($_, 1) || croak("Wide character in argument"),
    length() < 256 || croak "Argument too long" for @args;

    my $minor = delete $options{Minor};
    if (defined($minor)) {
        $minor =~ /\A\d+\z/ || croak "Non numeric minor '$minor'";
        $minor < 16 || croak "Minor '$minor' is too big (max 4 bits)";
    } else {
        $minor = 0;
    }

    $session->{result} = delete $options{Result};

    croak "Unknown options ", join(", ", keys %options) if %options;

    $session->{parent}->send
        ($session, $minor, AUTHOR,
         pack("C" . (8+@args) . "(a*)*",
              $method, $privilege, $type, $service, length($user),
              length($port), length($rem_addr), scalar @args,
              map(length, @args), $user, $port, $rem_addr, @args));
}

sub got {
    my $session = shift;
    die "Client authorization session received a packet with invalid sequence number $session->{seq_no}\n" if $session->{seq_no} != 2;
    # Number 2, must be a response packet
    die "Short authorization response packet\n" if length($_[0]) < 6;
    my ($nr_args, $msg_len, $data_len) = unpack("xCnn", $_[0]);
    my $left = length($_[0]) - (6+$nr_args+$msg_len+$data_len);
    die "Short authorization response packet\n" if $left < 0;
    my $read_args = 'C@' .(6+$nr_args). "a${msg_len}a${data_len}";
    $read_args .= "a$_", $left-=$_ for unpack("\@6C$nr_args", $_[0]);
    die "Bad authorization response packet length\n" if $left;
    my ($status, $message, $data, @args) = unpack($read_args, shift);
    ($session->{result} || $session->{options}{AuthorizeResult} ||
     die "No 'AuthorizeResult' handler\n")->
     ($session,
      Minor	=> shift,
      Message => $message,
      Data => $status == AUTHOR_STATUS_FOLLOW ? WEC::TacacsPlus::Session::unpack_follow($data):$data,
      $author_status2name[$status] ?
      (Status => $author_status2name[$status],
       $author_status2name[$status]	=> 1) :
      (Status => $status),
      Args => \@args);
    $session->_drop if $session->{parent};
}

package WEC::TacacsPlus::Session::Server::Account;
use Carp;
use WEC::TacacsPlus::Constants
    qw(ACCT ACCT_STATUS_SUCCESS ACCT_STATUS_FOLLOW);

our $VERSION = "0.01";
use base qw(WEC::TacacsPlus::Session);

our @CARP_NOT = qw(WEC::TacacsPlus::Connection);

sub got {
    my $session = shift;
    die "Server accounting session received a packet with invalid sequence number $session->{seq_no}\n" if $session->{seq_no} != 1;
    die "No Account request handler\n" unless $session->{options}{Account};
    # Odd numbered, must be a request
    my $left = length($_[0]) - 9;
    die "Short accounting request packet\n" if $left < 0;
    my ($user_len, $port_len, $rem_addr_len, $nr_args) =
        unpack('@5CCCC', $_[0]);
    $left -= $nr_args;
    my $read_args = 'CCCCC@' . (9+$nr_args);
    $read_args .= "a$_", $left-=$_ for
        $user_len, $port_len, $rem_addr_len, unpack("\@9C$nr_args", $_[0]);
    die "Bad accounting request packet length\n" if $left;

    my ($flags, $method, $privilege, $type, $service, $user, $port,
        $rem_addr, @args) = unpack($read_args, shift);

    my @result = ($session,
                  Minor	=> shift,
                  Flags	=> $flags,
                  Method	=> $authen_method2name[ $method]  || $method,
                  Privilege	=> $privilege,
                  Type	=> $authen_type2name[   $type]	  || $type,
                  Service	=> $authen_service2name[$service] || $service,
                  User => $user, Port => $port, RemoteAddress => $rem_addr,
                  Args	=> \@args);

    for (keys %account_event) {
        next unless $flags & $account_event{$_};
        $flags &= ~$account_event{$_};
        push @result, ucfirst(lc) . "Event" => 1;
    }
    push @result, ExtraFlags => $flags if $flags;

    $session->{options}{Account}->(@result);
    # Don't $session->_drop. The replying will do the drop
    return if $session->{seq_no} == 2;
    die "Weird jump in sequence number from 1 to $session->{seq_no}\n" if 
        $session->{seq_no} != 1;
    die "No accounting reply was sent\n" unless $session->{ended};
}

sub reply {
    my ($session, %options) = @_;
    $session->{parent} ||
        croak "Cannot reply on a dropped accounting session";
    # Should be impossible, since replying will drop the session
    croak "Assertion: Unexpected sequence number $session->{seq_no}" if
        $session->{seq_no} != 1;
    eval {
        defined(my $status = exists $options{Status} ?
                delete $options{Status} : ACCT_STATUS_SUCCESS) ||
                croak "Undefined accounting reply status value";
        if ($status !~ /\A\d+\z/) {
            $status = $account_name2status{uc($status)} ||
                croak "Unknown accounting status '$status'";
        }
        $status < 256 || croak "Status $status is too big";

        my $message = delete $options{Message};
        $message = "" unless defined($message);
        utf8::downgrade($message, 1) || croak "Wide character in Message";
        length($message) < 2**16 || croak "Message field too long";

        my $data = delete $options{Data};
        $data = "" unless defined($data);
        $data = WEC::TacacsPlus::Session::pack_follow($data) if $status == ACCT_STATUS_FOLLOW;
        utf8::downgrade($data, 1) || croak "Wide character in Data";
        length($data) < 2**16 || croak "Data field too long";

        my $minor = delete $options{Minor};
        if (defined($minor)) {
            $minor =~ /\A\d+\z/ || croak "Non numeric minor '$minor'";
            $minor < 16 || croak "Minor '$minor' is too big (max 4 bits)";
        } else {
            $minor = 0;
        }

        croak "Unknown options ", join(", ", keys %options) if %options;

        $session->{parent}->send
            ($session, $minor, ACCT,
             pack("nnCa*a*",
                  length($message), length($data), $status, $message, $data));
        $session->_drop;
    };
    return unless $@;
    $@ =~ s/ at .* line \d+//g;
    $@ =~ s/\n\z//;
    # This leaks data to the clients. Probably should be configurable
    # Reply already does $session->_drop
    $session->reply(Status	=> "Error", 
                    Message => $server_error_message,
                    Data	=> $@);
    # die $@;
}

package WEC::TacacsPlus::Session::Client::Account;
use Carp;
use WEC::TacacsPlus::Constants
    qw(ACCT ACCT_STATUS_FOLLOW AUTHEN_METH_NOT_SET AUTHEN_TYPE_ASCII
       ACCT_FLAG_STOP ACCT_FLAG_START ACCT_FLAG_WATCHDOG);

our $VERSION = "0.01";
use base qw(WEC::TacacsPlus::Session);

our @CARP_NOT = qw(WEC::TacacsPlus::Connection);

sub _account {
    my ($session, %options) = @_;
    croak "Not a virgin session" if $session->{seq_no};

    defined(my $event = delete $options{Event}) ||
        croak "No Event specified";
    if ($event !~ /\A\d+\z/) {
        my $flags = 0;
        $flags |= $account_event{$_} || croak "Unknown accounting event '$_'"
            for split/\|/, uc($event);
        $event = $flags;
    }
    $event < 256 || croak "Event $event is too big";
    croak "START and STOP events are mutually exclusive" if
        ($event & (ACCT_FLAG_STOP | ACCT_FLAG_START)) == (ACCT_FLAG_STOP | ACCT_FLAG_START);
    croak "WATCHDOG and STOP events are mutually exclusive" if
        ($event & (ACCT_FLAG_STOP | ACCT_FLAG_WATCHDOG)) == (ACCT_FLAG_STOP | ACCT_FLAG_WATCHDOG);

    my $method = delete $options{Method};
    $method = AUTHEN_METH_NOT_SET unless defined($method);
    if ($method !~ /\A\d+\z/) {
        defined(my $m = $authen_method{uc($method)}) ||
                croak "Unknown authentication method '$method'";
        $method = $m;
    }
    $method < 256 || croak "Method $method is too big";

    my $priv = delete $options{Privilege};
    $priv = "USER" unless defined($priv);
    defined(my $privilege = $priv_level{uc($priv)}) ||
        croak "Invalid privilege level '$priv'";

    my $type = delete $options{Type};
    if (!defined($type)) {
        $type = AUTHEN_TYPE_ASCII;
    } elsif ($type !~ /\A\d+\z/) {
        $type = $authen_type{uc($type)} ||
            croak "Unknown authentication type '$type'";
    }
    $type < 256 || croak "Type $type is too big";

    my $service = delete $options{Service};
    if (!defined($service)) {
        defined($service = $authen_type_service{$type}) ||
            croak "No service known for authentication type '$type'";
    } elsif ($service !~ /\A\d+\z/) {
        defined(my $s = $authen_service{uc($service)}) ||
            croak "Unknown authentication service '$service'";
        $service = $s;
    }
    $service < 256 || croak "Service $service is too big";

    my $user = delete $options{User};
    $user = "" unless defined($user);
    utf8::downgrade($user, 1) || croak "Wide character in User";
    length($user) < 256 || croak "User field too long";

    exists $options{Port} || croak "No Port specified";
    my $port = delete $options{Port};
    $port = "" unless defined($port);
    utf8::downgrade($port, 1) || croak "Wide character in Port";
    length($port) < 256 || croak "Port field too long";

    exists $options{RemoteAddress} || croak "No RemoteAddress specified";
    my $rem_addr = delete $options{RemoteAddress};
    $rem_addr = "" unless defined($rem_addr);
    utf8::downgrade($rem_addr, 1) || croak "Wide character in RemoteAddress";
    length($rem_addr) < 256 || croak "RemoteAddress field too long";

    my $args = delete $options{Args};
    $args = [] unless defined($args);
    croak "Args is not an array reference" unless ref($args) eq "ARRAY";
    @$args < 256 || croak "Too many (", scalar @$args, ") arguments";
    my @args = @$args;
    utf8::downgrade($_, 1) || croak("Wide character in argument"),
    length() < 256 || croak "Argument too long" for @args;

    my $minor = delete $options{Minor};
    if (defined($minor)) {
        $minor =~ /\A\d+\z/ || croak "Non numeric minor '$minor'";
        $minor < 16 || croak "Minor '$minor' is too big (max 4 bits)";
    } else {
        $minor = 0;
    }

    $session->{result} = delete $options{Result};

    croak "Unknown options ", join(", ", keys %options) if %options;

    $session->{parent}->send
        ($session, $minor, ACCT,
         pack("C" . (9+@args) . "(a*)*",
              $event, $method, $privilege, $type, $service, length($user),
              length($port), length($rem_addr), scalar @args,
              map(length, @args), $user, $port, $rem_addr, @args));
}

sub got {
    my $session = shift;
    die "Client accounting session received a packet with invalid sequence number $session->{seq_no}\n" if $session->{seq_no} != 2;
    # Even numbered, must be a reply packet
    die "Short accounting reply packet\n" if length($_[0]) < 5;
    my ($msg_len, $data_len, $status) = unpack("nnC", $_[0]);
    die "Bad accounting reply packet length\n" if
        length($_[0]) != $msg_len + $data_len + 5;
    my ($message, $data) = unpack("x5a${msg_len}a${data_len}", shift);

    # print STDERR "status=$status,server msg='$message',data='$data'\n";
    ($session->{result} || $session->{options}{AccountResult} ||
     die "No 'AccountResult' handler\n")->
     ($session,
      Minor	=> shift,
      Message => $message,
      Data => $status == ACCT_STATUS_FOLLOW ? WEC::TacacsPlus::Session::unpack_follow($data): $data,
      $account_status2name[$status] ?
      (Status => $account_status2name[$status],
       $account_status2name[$status]	=> 1) :
      (Status => $status));
    $session->_drop if $session->{parent};
}

1;
__END__
