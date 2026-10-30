# Run inside the sandbox by the tests: reports what the confined process can
# and cannot do. One "name: result" line per check, where result is "ok",
# "denied" (EACCES/EPERM, i.e. blocked by Landlock) or "failed (<errno>)".
use strict;
use warnings;
use Errno;
use Socket;

my $home = $ENV{HOME};

sub report {
    my ($name, $ok) = @_;
    my $result = $ok ? 'ok'
               : ($!{EACCES} || $!{EPERM}) ? 'denied'
               : "failed ($!)";
    print "$name: $result\n";
}

sub connect_to {
    my ($proto, $host, $port) = @_;
    my $type = $proto eq 'udp' ? SOCK_DGRAM : SOCK_STREAM;
    socket(my $s, PF_INET, $type, 0) or return;
    return connect($s, pack_sockaddr_in($port, inet_aton($host)));
}

report('read-home', open(my $f1, '<', "$home/secret"));
report('create-home', open(my $f2, '>', "$home/created"));
report('read-ssh', open(my $f3, '<', "$home/.ssh/existing"));
report('create-ssh', open(my $f4, '>', "$home/.ssh/created"));
report('truncate-home', truncate("$home/secret", 0));

# Arguments: extra paths to try reading, and proto:host:port to connect to
for my $arg (@ARGV) {
    if (my ($proto, $host, $port) = $arg =~ /^(tcp|udp):([0-9.]+):([0-9]+)$/) {
        report("connect-$arg", connect_to($proto, $host, $port));
    } else {
        report("read-$arg", open(my $fh, '<', $arg));
    }
}

print 'env: ', join(',', sort keys %ENV), "\n";
