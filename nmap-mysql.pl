#!/usr/bin/perl

use Nmap::Scanner;
use Date::Format;
use Getopt::Long;
use DBI;

my $dbname = "";
my $dbhost = "";
my $dbuser = "";
my $dbpass = "";

GetOptions(
    'dbname=s'     => \$dbname,
    'dbhost=s'     => \$dbhost,
    'dbuser=s'     => \$dbuser,
    'dbpass=s'     => \$dbpass,
);

if (!$dbname || !$dbhost || !$dbuser || !$dbpass ) {
    # TODO: usage() && -h
    die("Not enough parameteres");
}

our $dbh = DBI->connect("DBI:mysql:$dbname", $dbuser, $dbpass)
        or die("ERROR: Could not connect to MYSQL database - " . $DBI::errstr);

check_tables($dbname) or create_tables();

open LOG, ">>/var/log/nmap-mysql.log";

my $nmap = new Nmap::Scanner;

$nmap->register_scan_complete_event(\&scan_complete);

$nmap->tcp_syn_scan();
$nmap->add_scan_port('1-1024');
$nmap->guess_os();

$targets  = $dbh->selectall_hashref('SELECT * FROM targets', 'id');
$num_rows = scalar keys %$targets;

foreach my $id (keys %$targets) {
    $nmap->add_target($targets->{$id}->{target});
}

my $results  = $nmap->scan();
my $nmap_run = $results->nmap_run();

my $start_time   = $nmap_run->start();
my $finish_time  = $nmap_run->run_stats()->finished()->time();
my $elapsed_time = $finish_time - $start_time;
my $total_hosts  = $nmap_run->run_stats()->hosts()->total();

sub scan_complete() {

    use Switch;

    our $dbh;

    my $self        = shift;
    my $host        = shift;
    my $hostname    = $host->hostname();
    my ($osmatches) = $host->os()? $host->os()->osmatches() : undef;
    my $os          = $osmatches? $osmatches->name() : undef;
    my $status      = ($host->status() eq "up")? 1 : 0;
    my $ports       = $host->get_port_list();
    my @addresses   = $host->addresses();
    my $time        = time2str("%C", time);

    print LOG ("[$time] ", $hostname, " is ", $host->status(), "\n");

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

sub check_tables {

    my $dbname = shift;

    my @nmap_tables  = ('hosts', 'targets', 'host_ports');
    my @tables_in_db = $dbh->tables('', $dbname, '', '');
    my $sql_quote    = $dbh->get_info(29);

    my %tables;
    @tables{@tables_in_db} = ();

    foreach my $table (@nmap_tables) {

        my $table_name = $sql_quote . $dbname . $sql_quote . '.' . $sql_quote . $table . $sql_quote;

        if (!exists $tables{$table_name}) {
            return 0;
        }
    }    

    return 1;

}

sub create_tables {

    our $dbh;

    my %sql = ();

    $sql{'targets'} = q{
CREATE TABLE IF NOT EXISTS `targets` (
    id int(11) PRIMARY KEY AUTO_INCREMENT,
    target VARCHAR(64)
);
};

    $sql{'hosts'} = q{
CREATE TABLE IF NOT EXISTS `hosts` (
  `id` int(20) PRIMARY KEY AUTO_INCREMENT,
  `ip_address` varchar(20) DEFAULT NULL,
  `mac_address` varchar(24) DEFAULT NULL,
  `hostname` varchar(64) DEFAULT NULL,
  `os` varchar(64) DEFAULT NULL,
  `scan_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `status` int(1) DEFAULT NULL
);
};

    $sql{'host_ports'} = q{
CREATE TABLE IF NOT EXISTS `host_ports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `host_id` int(11) DEFAULT NULL,
  `port_number` char(5) DEFAULT NULL,
  `protocol` varchar(20) DEFAULT NULL,
  `state` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
};

    foreach my $create_table (values %sql) {
        $stmt = $dbh->prepare($create_table);
        $stmt->execute() or die("ERROR: Could not create required tables");
    }

}
