package ProFTPD::Tests::Modules::mod_md5;

use lib qw(t/lib);
use base qw(Test::Unit::TestCase ProFTPD::TestSuite::Child);
use strict;

use Digest::MD5 qw(md5_hex);
use File::Path qw(mkpath rmtree);
use File::Spec;
use IO::Handle;
use POSIX qw(:fcntl_h);

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  md5_path => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  md5_path_chrooted => {
    order => ++$order,
    test_class => [qw(forking rootprivs)],
  },

  md5_stor => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  md5_retr => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  md5_sftp_stor => {
    order => ++$order,
    test_class => [qw(mod_sftp forking)],
  },

  md5_sftp_retr => {
    order => ++$order,
    test_class => [qw(mod_sftp forking)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub set_up {
  my $self = shift;
  $self->{tmpdir} = testsuite_get_tmp_dir();

  # Create temporary scratch dir
  eval { mkpath($self->{tmpdir}) };
  if ($@) {
    my $abs_path = File::Spec->rel2abs($self->{tmpdir});
    die("Can't create dir $abs_path: $@");
  }

  # Make sure that mod_sftp does not complain about permissions on the hostkey
  # files.

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_md5/ssh_host_rsa_key');
  my $dsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_md5/ssh_host_dsa_key');

  unless (chmod(0400, $rsa_host_key, $dsa_host_key)) {
    die("Can't set perms on $rsa_host_key, $dsa_host_key: $!");
  }

}

sub tear_down {
  my $self = shift;

  # Remove temporary scratch dir
  if ($self->{tmpdir}) {
    eval { rmtree($self->{tmpdir}) };
  }

  undef $self;
}

sub md5_path {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/md5.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/md5.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/md5.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/md5.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/md5.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $md5_file = File::Spec->rel2abs("$tmpdir/test.txt.md5");
  my $plaintext = "Hello, World!\n";

  my $expected_md5 = md5_hex($plaintext);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_md5.c' => {
        MD5Engine => 'on',
        MD5Path => '~',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.txt');
      unless ($conn) {
        die("Failed to STOR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      $conn->write($plaintext, length($plaintext));
      $conn->close();

      my ($resp_code, $resp_msg);
      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Transfer complete";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client->quit();

      # Make sure the expected 'test.txt.md5' file exists
      unless (-f $md5_file) {
        die("MD5 file $md5_file does not exist as expected");
      }

      if (open(my $fh, "< $md5_file")) {
        binmode($fh);
        my $md5_text = <$fh>;
        chomp($md5_text);
        close($fh);

        unless ($md5_text =~ /^(\S+)  \S+$/) {
          die("Unexpectedly formatted .md5 text: '$md5_text'");
        }

        my $file_md5 = $1;

        $self->assert($expected_md5 eq $file_md5,
          test_msg("Expected '$expected_md5', got '$file_md5'"));

      } else {
        die("Can't open $md5_file: $!");
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub md5_path_chrooted {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/md5.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/md5.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/md5.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/md5.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/md5.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $md5_file = File::Spec->rel2abs("$tmpdir/test.txt.md5");
  my $plaintext = "Hello, World!\n";

  my $expected_md5 = md5_hex($plaintext);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    DefaultRoot => $home_dir,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_md5.c' => {
        MD5Engine => 'on',
        MD5Path => '~',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.txt');
      unless ($conn) {
        die("Failed to STOR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      $conn->write($plaintext, length($plaintext));
      $conn->close();

      my ($resp_code, $resp_msg);
      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Transfer complete";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client->quit();

      # Make sure the expected 'test.txt.md5' file exists
      unless (-f $md5_file) {
        die("MD5 file $md5_file does not exist as expected");
      }

      if (open(my $fh, "< $md5_file")) {
        binmode($fh);
        my $md5_text = <$fh>;
        chomp($md5_text);
        close($fh);

        unless ($md5_text =~ /^(\S+)  \S+$/) {
          die("Unexpectedly formatted .md5 text: '$md5_text'");
        }

        my $file_md5 = $1;

        $self->assert($expected_md5 eq $file_md5,
          test_msg("Expected '$expected_md5', got '$file_md5'"));

      } else {
        die("Can't open $md5_file: $!");
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub md5_stor {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/md5.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/md5.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/md5.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/md5.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/md5.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  my $test_md5 = File::Spec->rel2abs("$tmpdir/test.txt.md5");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_md5.c' => {
        MD5Engine => 'on',
        MD5Path => $home_dir,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  my $buf = "Hello, World\n";

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->stor_raw("test.txt");
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() .
          $client->response_msg());
      }

      $conn->write($buf, length($buf));
      $conn->close();

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  $self->assert(-f $test_md5,
    test_msg("$test_md5 file not present as expected"));

  # Now, read in the generated .md5 file, and verify that it's MD5 checksum
  # is what we expect.
  my $actual_md5;
  if (open(my $fh, "< $test_md5")) {
    my $line = <$fh>;
    chomp($line);
    close($fh);

    if ($line =~ /(\S+)\s+(\S+)/) {
      $actual_md5 = $1;

    } else {
      die("Line '$line' did not match regex");
    }

  } else {
    die("Can't read $test_md5: $!");
  }

  my $expected_md5 = md5_hex($buf);
  $self->assert($expected_md5 eq $actual_md5,
    test_msg("Expected '$expected_md5', got '$actual_md5'"));

  unlink($log_file);
}

sub md5_retr {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/md5.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/md5.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/md5.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/md5.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/md5.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  my $test_md5 = File::Spec->rel2abs("$tmpdir/test.txt.md5");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_md5.c' => {
        MD5Engine => 'on',
        MD5Path => $home_dir,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  my $buf = "Hello, World\n";

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      $client->login($user, $passwd);
      $client->type('binary');

      my $conn = $client->stor_raw("test.txt");
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() .
          $client->response_msg());
      }

      $conn->write($buf, length($buf));
      $conn->close();

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected;

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      # According to:
      #
      #  http://forums.proftpd.org/smf/index.php/topic,3050.0
      #
      # the .md5 file changes after $file is downloaded.  So let's download
      # it, and see what happens.

      $conn = $client->retr_raw('test.txt');
      unless ($conn) {
        die("RETR test.txt failed: " . $client->response_code() .
          $client->response_msg());
      }

      my $buf;
      my $tmp;
      while ($conn->read($tmp, 8192)) {
        $buf .= $tmp;
      }

      $conn->close();

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = 'Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  $self->assert(-f $test_md5,
    test_msg("$test_md5 file not present as expected"));

  # Now, read in the generated .md5 file, and verify that it's MD5 checksum
  # is what we expect.
  my $actual_md5;
  if (open(my $fh, "< $test_md5")) {
    my $line = <$fh>;
    chomp($line);
    close($fh);

    if ($line =~ /(\S+)\s+(\S+)/) {
      $actual_md5 = $1;

    } else {
      die("Line '$line' did not match regex");
    }

  } else {
    die("Can't read $test_md5: $!");
  }

  my $expected_md5 = md5_hex($buf);
  $self->assert($expected_md5 eq $actual_md5,
    test_msg("Expected '$expected_md5', got '$actual_md5'"));

  unlink($log_file);
}

sub md5_sftp_stor {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/md5.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/md5.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/md5.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/md5.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/md5.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  my $test_md5 = File::Spec->rel2abs("$tmpdir/test.txt.md5");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_md5/ssh_host_rsa_key');
  my $dsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_md5/ssh_host_dsa_key');

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'command:10 fsio:10',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_md5.c' => {
        MD5Engine => 'on',
        MD5Path => $home_dir,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $log_file",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  my $buf = "Hello, World\n";

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  require Net::SSH2;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($user, $passwd)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $fh = $sftp->open('test.txt', O_WRONLY|O_CREAT|O_TRUNC, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.txt: [$err_name] ($err_code)");
      }

      print $fh $buf;

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $ssh2->disconnect();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  $self->assert(-f $test_md5,
    test_msg("$test_md5 file not present as expected"));

  # Now, read in the generated .md5 file, and verify that it's MD5 checksum
  # is what we expect.
  my $actual_md5;
  if (open(my $fh, "< $test_md5")) {
    my $line = <$fh>;
    chomp($line);
    close($fh);

    if ($line =~ /(\S+)\s+(\S+)/) {
      $actual_md5 = $1;

    } else {
      die("Line '$line' did not match regex");
    }

  } else {
    die("Can't read $test_md5: $!");
  }

  my $expected_md5 = md5_hex($buf);
  $self->assert($expected_md5 eq $actual_md5,
    test_msg("Expected '$expected_md5', got '$actual_md5'"));

  unlink($log_file);
}

sub md5_sftp_retr {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/md5.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/md5.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/md5.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/md5.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/md5.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  my $test_md5 = File::Spec->rel2abs("$tmpdir/test.txt.md5");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_md5/ssh_host_rsa_key');
  my $dsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_md5/ssh_host_dsa_key');

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_md5.c' => {
        MD5Engine => 'on',
        MD5Path => $home_dir,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $log_file",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  my $buf = "Hello, World\n";

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  require Net::SSH2;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($user, $passwd)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $fh = $sftp->open('test.txt', O_WRONLY|O_CREAT|O_TRUNC, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.txt: [$err_name] ($err_code)");
      }

      print $fh $buf;

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $fh = $sftp->open('test.txt', O_RDONLY);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.txt: [$err_name] ($err_code)");
      }

      my $res;
      my $tmp;

      my $res = $fh->read($tmp, 8192);
      while ($res) {
        $res = $fh->read($tmp, 8192);
      }

      $fh = undef;

      $ssh2->disconnect();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  $self->assert(-f $test_md5,
    test_msg("$test_md5 file not present as expected"));

  # Now, read in the generated .md5 file, and verify that it's MD5 checksum
  # is what we expect.
  my $actual_md5;
  if (open(my $fh, "< $test_md5")) {
    my $line = <$fh>;
    chomp($line);
    close($fh);

    if ($line =~ /(\S+)\s+(\S+)/) {
      $actual_md5 = $1;

    } else {
      die("Line '$line' did not match regex");
    }

  } else {
    die("Can't read $test_md5: $!");
  }

  my $expected_md5 = md5_hex($buf);
  $self->assert($expected_md5 eq $actual_md5,
    test_msg("Expected '$expected_md5', got '$actual_md5'"));

  unlink($log_file);
}

1;
