#!/usr/bin/perl

use Nmap::Scanner;
use Getopt::Long;
use DBI;

my $db     = "";
my $host   = "";
my $user   = "";
my $pass   = "";
my $target = "";

GetOptions(
    'dbname=s' => \$db,
    'dbhost=s' => \$host,
    'dbuser=s' => \$user,
    'dbpass=s' => \$pass,
    'target=s' => \$target
);

if (!$db || !$host || !$user || !$pass || !$target) {
    # TODO: usage() && -h
    die("Not enough parameteres");
}

our $dbh = DBI->connect("DBI:mysql:$db", $user, $pass)
        or die("ERROR: Could not connect to MYSQL database - " . $DBI::errstr);

my $nmap = new Nmap::Scanner;

$nmap->register_scan_complete_event(\&scan_complete);

$nmap->tcp_syn_scan();
$nmap->add_scan_port('1-1024');
$nmap->guess_os();
$nmap->add_target($target);

my $results  = $nmap->scan();
my $nmap_run = $results->nmap_run();

my $start_time   = $nmap_run->start();
my $finish_time  = $nmap_run->run_stats()->finished()->time();
my $elapsed_time = $finish_time - $start_time;
my $total_hosts  = $nmap_run->run_stats()->hosts()->total();

sub scan_complete() {

    our $dbh;

    use Switch;

    my $self        = shift;
    my $host        = shift;
    my $hostname    = $host->hostname();
    my ($osmatches) = $host->os()? $host->os()->osmatches() : undef;
    my $os          = $osmatches? $osmatches->name() : undef;
    my $status      = ($host->status() eq "up")? 1 : 0;
    my $ports       = $host->get_port_list();
    my @addresses   = $host->addresses();

    for my $addr (@addresses) {
        switch ($addr->addrtype()) {
            case "mac"  { $macaddr = $addr->addr(); }
            case "ipv4" { $ipaddr  = $addr->addr(); }
            case "ipv6" { $ipaddr  = $addr->addr(); }
        }
    }

    $insert = "INSERT INTO hosts VALUES (NULL, ?, ?, ?, ?, NULL, ?);";
    $stmt   = $dbh->prepare($insert);

    $stmt->execute($ipaddr, $macaddr, $hostname, $os, $status)
        or die("ERROR: Could not insert scan information - " . $dbh->errstr);

    $host_id = $dbh->{ q{mysql_insertid} };

    $insert_ports = "INSERT INTO host_ports VALUES (?, ?, ?, ?, ?)";
    $stmt_ports   = $dbh->prepare($insert_ports);

    while (my $p = $ports->get_next()) {
        $stmt_ports->execute(undef, $host_id, $p->portid(), $p->protocol(), $p->state())
            or die("ERROR: Could not insert port information - " . $dbh->errstr);
    }

}
