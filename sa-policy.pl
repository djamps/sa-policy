#!/usr/bin/perl -w
#
# The MIT License (MIT)
#
# Copyright (c) 2015 Randy McAnally / amps@djlab.com
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

use strict;
use File::Tail;
use DBI;
use Log::Log4perl;
use Fcntl qw(:flock);
use Net::CIDR;

my $VERSION = "1.0.3";

## Only allow once instance!   todo: make it less hacky
unless (flock(DATA, LOCK_EX|LOCK_NB)) {
    die "$0 is already running. Exiting.\n";
}

my $config;

$config->{mysql_host} = 'host';
$config->{mysql_port} = 3306;
$config->{mysql_user} = 'user';
$config->{mysql_password} = 'pass';
$config->{mysql_db} = 'db';

# Basic settings
$config->{primary} = 1; # Set to 1 on primary node, 0 on all other nodes
$config->{maillog_path} = '/var/log/maillog'; # Path to postfix maillog
$config->{log_file} = '/var/log/sa-policy.log'; # Path for logfile
$config->{debug} = 1;
$config->{debug_interval} = 30; # Interval between stats in logfile
$config->{infected_is_spam} = 1; # Treat viruses as SPAM and blacklist accordingly

# IP's and ranges that should never be blacklisted
my @whitelist = Net::CIDR::cidradd(
    "10.0.0.0/8",
    "192.168.0.0/16",
    "127.0.0.0/8"
);

## The following settings only matter on the primary node (primary = 1)
$config->{purge_age} = 86400; # Purge log records older than n seconds
$config->{purge_interval} = 1800; # Purge old records every n seconds
$config->{process_interval} = 30; # Look for new IP bans every n seconds
$config->{spam_score} = 6; # Minimum score to consider for blacklisting
$config->{max_spam_per_interval} = 5;  #  n spams per interval = ban time
$config->{spam_interval} = 600; # Interval of n seconds
$config->{blacklist_time} = 1800; # Blacklist IPs for n seconds (multiplied each time a ban reoccurs)

## Do not touch anything below

## Init logger
my $log_conf ="  log4perl.rootLogger   = DEBUG, LOGFILE, STDOUT
   log4perl.appender.LOGFILE           = Log::Log4perl::Appender::File
   log4perl.appender.LOGFILE.filename  = $config->{log_file}
   log4perl.appender.LOGFILE.mode      = append
   log4perl.appender.LOGFILE.recreate  = 1
   log4perl.appender.LOGFILE.layout    = Log::Log4perl::Layout::PatternLayout
   log4perl.appender.LOGFILE.layout.ConversionPattern = %d %p %m %n
   log4perl.appender.STDOUT           = Log::Log4perl::Appender::Screen
   log4perl.appender.STDOUT.stderr    = 0
   log4perl.appender.STDOUT.layout    = Log::Log4perl::Layout::PatternLayout
   log4perl.appender.STDOUT.layout.ConversionPattern = %d %p %m %n
";
Log::Log4perl::init(\$log_conf);
my $log = Log::Log4perl->get_logger();

## Catch die() and log it before dying.
$SIG{__DIE__} = sub {
    if($^S) {

        # We're in an eval {} and don't want log
        # this message but catch it later
        return;
    }
    $Log::Log4perl::caller_depth++;
    $log->logdie(@_);
};

$log->info("$0 $VERSION starting");

## Connect to DB
my $dsn = "DBI:mysql:database=$config->{mysql_db};host=$config->{mysql_host};port=$config->{mysql_port}";
my $dbh = DBI->connect($dsn, $config->{mysql_user}, $config->{mysql_password})
  || die "MySQL connection failed";
$log->info("DB connected");

my $last_purge = 0;
my $last_process = 0;
my $last_debug = time() + $config->{debug_interval};
my $stat = {};
&init_stats;

my $file=File::Tail->new($config->{maillog_path});
while (defined(my $line=$file->read)) {

    # Checkif we need to purge old records
    my $time = time();
    if ($config->{primary} && $last_purge < $time - $config->{purge_interval}) {
        &purge_tables();
        $last_purge = $time;
    }

    # Check if we need to create bans
    if ($config->{primary} && $last_process < $time - $config->{process_interval}) {
        &process_log();
        $last_process = $time;
    }

    # Check if we need to log stats
    if ($last_debug < $time - $config->{debug_interval}) {
        &log_stats();
        $last_debug = $time;
    }

    next if !($line =~ m/(Blocked SPAM|Passed CLEAN|Blocked INFECTED)/);
    my $class = ($line =~ m/Passed CLEAN/)?"HAM":"SPAM";
    my $hits = 0;
    if ( $line =~ m/Blocked INFECTED/ && $config->{infected_is_spam} ) {
        $hits = 999;
    } else {
        $line =~ m/Hits: (\d+\.?\d*)/ and $hits = $1;
    }
    $stat->{$class}++;
    my $ip;
    $line =~ /\[((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))\]/ and $ip = $1;
    $line =~ /\[(([0-9a-fA-F]{4}|0)(\:([0-9a-fA-F]{4}|0)){7})\]/ and $ip = $1;
    ## Local deliveries don't have an IP, skip these
    next if !$ip;
    log_sql($ip,$hits,$class);

}

sub log_stats{
    $log->debug("$stat->{blacklisted} new blacklistings, $stat->{SPAM} spam, $stat->{HAM} ham");
    if ($stat->{expired_blacklist} > 0 || $stat->{expired_log} > 0) {
        $log->debug("Purged $stat->{expired_log} log entries, $stat->{expired_blacklist} blacklist entries, and $stat->{expired_stats} host stats");
    }
    &init_stats;
}

sub init_stats{
    $stat = {
        blacklisted=>0,
        SPAM=>0,
        HAM=>0,
        expired_blacklist=>0,
        expired_log=>0,
        expired_stats=>0
    };
}

sub purge_tables{
    ## Delete old log records
    my $sql = "DELETE FROM sa_policy_log WHERE time < NOW() - INTERVAL ? SECOND;";
    my $sth = $dbh->prepare($sql)
      || die "Error:" . $dbh->errstr . "\n";
    $sth->execute($config->{purge_age})
      ||  die "Error:" . $sth->errstr . "\n";
    if (my $n = $sth->rows) {
        $stat->{expired_log}=$stat->{expired_log}+$n;
    }
    ## Delete expired blacklistings
    $sql = "DELETE FROM sa_policy_blacklist WHERE expires < NOW() - INTERVAL ? SECOND;";
    $sth = $dbh->prepare($sql)
      || die "Error:" . $dbh->errstr . "\n";
    $sth->execute($config->{purge_age})
      ||  die "Error:" . $sth->errstr . "\n";
    if (my $n = $sth->rows) {
        $stat->{expired_blacklist}=$stat->{expired_blacklist}+$n;
    }
    ## Delete old stat records of hosts not seen lately
    $sql = "DELETE FROM sa_policy_stats WHERE last_seen < NOW() - INTERVAL ? SECOND;";
    $sth = $dbh->prepare($sql)
      || die "Error:" . $dbh->errstr . "\n";
    $sth->execute($config->{purge_age})
      ||  die "Error:" . $sth->errstr . "\n";
    if (my $n = $sth->rows) {
        $stat->{expired_stats}=$stat->{expired_stats}+$n;
    }
}

sub process_log{
    ## Look for spam sources and blacklist them
    my $sql = "SELECT ip,count(ip) as count FROM sa_policy_log
        WHERE time > NOW() - INTERVAL ? SECOND
          AND hits > ?
        GROUP BY ip
        HAVING count(ip) >= ?;";
    my $sth = $dbh->prepare($sql)
      || die "Error:" . $dbh->errstr . "\n";
    $sth->execute($config->{spam_interval},$config->{spam_score},$config->{max_spam_per_interval})
      ||  die "Error:" . $sth->errstr . "\n";

    while (my @row = $sth->fetchrow) {
        if (Net::CIDR::cidrlookup($row[0], @whitelist)) {
            $log->debug("Not blacklisting ".$row[0]." due to whitelist");
            next;
        }
        ## Create the blacklist entry
        $sql = "INSERT IGNORE INTO sa_policy_blacklist (ip) VALUES (?);";
        my $sth2 = $dbh->prepare($sql)
          || die "Error:" . $dbh->errstr . "\n";
        $sth2->execute($row[0])
          ||  die "Error:" . $sth->errstr . "\n";

        ## Update the blacklist entry with details
        ## Multiply expiration time by number of listings
        ## to increase blocking time for repeat offenders

        $sql = "UPDATE sa_policy_blacklist SET
            spam_count = spam_count + ?,
            updates = updates + 1,
            expires = NOW() + INTERVAL (?*(updates + 1)) SECOND
            WHERE ip = ? AND expires <= NOW();";
        $sth2 = $dbh->prepare($sql)
          || die "Error:" . $dbh->errstr . "\n";
        $sth2->execute($row[1],$config->{blacklist_time},$row[0])
          ||  die "Error:" . $sth->errstr . "\n";

        if ($sth2->rows > 0) {
            $log->info("Blacklisted $row[0] for $row[1] spam messages in the last $config->{spam_interval} seconds");
            $stat->{blacklisted}++;
        }

    }

}

sub log_sql{
    my ($ip,$hits,$class) = @_;
    my $sql = "INSERT INTO sa_policy_log (ip,hits,time)
                VALUES (?,?,NOW());";

    my $sth = $dbh->prepare($sql)
      || die "Error:" . $dbh->errstr . "\n";
    $sth->execute($ip,$hits)
      ||  die "Error:" . $sth->errstr . "\n";

    $sql = "INSERT IGNORE INTO sa_policy_stats (ip,first_seen,last_seen) VALUES (?,NOW(),NOW());";
    $sth = $dbh->prepare($sql)
      || die "Error:" . $dbh->errstr . "\n";
    $sth->execute($ip)
      ||  die "Error:" . $sth->errstr . "\n";

    my $column = ($class =~ /SPAM/)?'spam_count':'ham_count';
    $sql = "UPDATE sa_policy_stats set $column = $column + 1, last_seen = NOW() WHERE ip = ?;";
    $sth = $dbh->prepare($sql)
      || die "Error:" . $dbh->errstr . "\n";
    $sth->execute($ip)
      ||  die "Error:" . $sth->errstr . "\n";

    return;
}

__DATA__
This exists so flock() code above works.
DO NOT REMOVE THIS DATA SECTION.

