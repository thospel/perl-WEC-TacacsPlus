package WEC::TacacsPlus::Constants;
use 5.008;
use warnings;
use strict;

use Exporter::Tidy
    Session		=> [qw(AUTHEN AUTHOR ACCT MAX_TYPE)],
    HeaderFlags		=> [qw(UNENCRYPTED_FLAG SINGLE_CONNECT_FLAG)],
    AuthenActions	=> [qw(AUTHEN_LOGIN AUTHEN_CHPASS AUTHEN_SENDPASS
			       AUTHEN_SENDAUTH)],
    Priveleges		=> [qw(PRIV_LVL_MAX PRIV_LVL_ROOT PRIV_LVL_USER
			       PRIV_LVL_MIN)],
    AuthenTypes		=> [qw(AUTHEN_TYPE_ASCII AUTHEN_TYPE_PAP
			       AUTHEN_TYPE_CHAP AUTHEN_TYPE_ARAP
			       AUTHEN_TYPE_MSCHAP)],
    AuthenServices	=> [qw(AUTHEN_SVC_NONE AUTHEN_SVC_LOGIN
			       AUTHEN_SVC_ENABLE AUTHEN_SVC_PPP AUTHEN_SVC_ARAP
			       AUTHEN_SVC_PT AUTHEN_SVC_RCMD AUTHEN_SVC_X25
			       AUTHEN_SVC_NASI AUTHEN_SVC_FWPROXY)],
    AuthenStatus	=> [qw(AUTHEN_STATUS_PASS AUTHEN_STATUS_FAIL
			       AUTHEN_STATUS_GETDATA AUTHEN_STATUS_GETUSER
			       AUTHEN_STATUS_GETPASS AUTHEN_STATUS_RESTART
			       AUTHEN_STATUS_ERROR AUTHEN_STATUS_FOLLOW)],
    ActionFlags		=> [qw(REPLY_FLAG_NOECHO CONTINUE_FLAG_ABORT)],

    AuthenMethods	=> [qw(AUTHEN_METH_NOT_SET AUTHEN_METH_NONE
			       AUTHEN_METH_KRB5 AUTHEN_METH_LINE
			       AUTHEN_METH_ENABLE AUTHEN_METH_LOCAL
			       AUTHEN_METH_TACACSPLUS AUTHEN_METH_GUEST
			       AUTHEN_METH_RADIUS AUTHEN_METH_KRB4
			       AUTHEN_METH_RCMD)],

    AuthorStatus	=> [qw(AUTHOR_STATUS_PASS_ADD AUTHOR_STATUS_PASS_REPL
                               AUTHOR_STATUS_FAIL AUTHOR_STATUS_ERROR
                               AUTHOR_STATUS_FOLLOW)],

    AccountingEvents	=> [qw(ACCT_FLAG_MORE ACCT_FLAG_START
			       ACCT_FLAG_STOP ACCT_FLAG_WATCHDOG)],
    AccountingStatus	=> [qw(ACCT_STATUS_SUCCESS ACCT_STATUS_ERROR
                               ACCT_STATUS_FOLLOW)],

    other		=> [qw(PORT)];

use constant {
    # Default port
    PORT	=> 49,

    # Header flags
    UNENCRYPTED_FLAG	=> 0x01,
    SINGLE_CONNECT_FLAG	=> 0x04,

    # Session types
    AUTHEN	=> 0x01, # Authentication
    AUTHOR	=> 0x02, # Authorization
    ACCT	=> 0x03, # Accounting
    MAX_TYPE	=> 3,

    # Authentication actions
    AUTHEN_LOGIN	=> 0x01,
    AUTHEN_CHPASS	=> 0x02,
    AUTHEN_SENDPASS	=> 0x03,	# deprecated
    AUTHEN_SENDAUTH	=> 0x04,

    # Privilige levels
    PRIV_LVL_MAX	=> 0x0f,
    PRIV_LVL_ROOT	=> 0x0f,
    PRIV_LVL_USER	=> 0x01,
    PRIV_LVL_MIN	=> 0x00,

    # Authentication types
    AUTHEN_TYPE_ASCII	=> 0x01,
    AUTHEN_TYPE_PAP	=> 0x02,
    AUTHEN_TYPE_CHAP	=> 0x03,
    AUTHEN_TYPE_ARAP	=> 0x04,
    AUTHEN_TYPE_MSCHAP	=> 0x05,

    # Service requesting authentication
    AUTHEN_SVC_NONE	=> 0x00,
    AUTHEN_SVC_LOGIN	=> 0x01,
    AUTHEN_SVC_ENABLE	=> 0x02,
    AUTHEN_SVC_PPP	=> 0x03,
    AUTHEN_SVC_ARAP	=> 0x04,
    AUTHEN_SVC_PT	=> 0x05,
    AUTHEN_SVC_RCMD	=> 0x06,
    AUTHEN_SVC_X25	=> 0x07,
    AUTHEN_SVC_NASI	=> 0x08,
    AUTHEN_SVC_FWPROXY	=> 0x09,

    # Authentication status
    AUTHEN_STATUS_PASS	   => 0x01,
    AUTHEN_STATUS_FAIL	   => 0x02,
    AUTHEN_STATUS_GETDATA  => 0x03,
    AUTHEN_STATUS_GETUSER  => 0x04,
    AUTHEN_STATUS_GETPASS  => 0x05,
    AUTHEN_STATUS_RESTART  => 0x06,
    AUTHEN_STATUS_ERROR	   => 0x07,
    AUTHEN_STATUS_FOLLOW   => 0x21,

    # Action modifier flags
    REPLY_FLAG_NOECHO	   => 0x01,
    CONTINUE_FLAG_ABORT	   => 0x01,

    # Authentication methods
    AUTHEN_METH_NOT_SET		=> 0x00,
    AUTHEN_METH_NONE		=> 0x01,
    AUTHEN_METH_KRB5		=> 0x02,
    AUTHEN_METH_LINE		=> 0x03,
    AUTHEN_METH_ENABLE		=> 0x04,
    AUTHEN_METH_LOCAL		=> 0x05,
    AUTHEN_METH_TACACSPLUS	=> 0x06,
    AUTHEN_METH_GUEST		=> 0x08,
    AUTHEN_METH_RADIUS		=> 0x10,
    AUTHEN_METH_KRB4		=> 0x11,
    AUTHEN_METH_RCMD		=> 0x20,

    AUTHOR_STATUS_PASS_ADD 	=> 0x01,
    AUTHOR_STATUS_PASS_REPL	=> 0x02,
    AUTHOR_STATUS_FAIL      	=> 0x10,
    AUTHOR_STATUS_ERROR     	=> 0x11,
    AUTHOR_STATUS_FOLLOW    	=> 0x21,

    # Accounting Event Types
    ACCT_FLAG_MORE	=> 0x01,	# deprecated
    ACCT_FLAG_START	=> 0x02,
    ACCT_FLAG_STOP	=> 0x04,
    ACCT_FLAG_WATCHDOG	=> 0x08,

    # Accounting status
    ACCT_STATUS_SUCCESS => 0x01,
    ACCT_STATUS_ERROR	=> 0x02,
    ACCT_STATUS_FOLLOW	=> 0x21,
};

1;
