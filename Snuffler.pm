#package Net::Snuffler;
package Snuffler;

use strict;
use warnings;
use Net::IP qw(ip_is_ipv4);

BEGIN {
  require Exporter;
  # set the version for version checking
  our $VERSION     = 0.4;
  # Inherit from Exporter to export functions and variables
  our @ISA         = qw(Exporter);
  # Functions and variables which are exported by default
  our @EXPORT      = qw(ValidateHost DeleteHost ExpireEntries AddHost UpdateHost Print BuildBPF );
}


#####################
## sub: BuildBPF( databasehandle dbh, hash_ref arguments)
##      Generates the BPF file based on the tracking database
sub BuildBPF
{
  my $dbh = shift or die;
  my $options = shift or die;
  my $OUTFH;

  # Expire out the entries prior to processing
  ExpireEntries($dbh, $options);

  # First we'll fetch all of the sensor IDs that are in use
  my %sensors;
  my $sth = $dbh->prepare("SELECT sensors FROM hosts WHERE sensors IS NOT NULL");
  $sth->execute() or die $dbh->errstr;

  my @row;
  while ( @row = $sth->fetchrow_array )
  {
    foreach my $sensor (@row)
    {
      $sensors{$sensor} = '';
    }
  }

  # Now construct the BPF for each bound sensor
  for my $sensor (keys %sensors)
  {
    my $filter;
    my $sth = $dbh->prepare("SELECT ip FROM hosts WHERE ( sensors LIKE '%$sensor%' OR sensors IS NULL )");
    $sth->execute() or die $dbh->errstr;

    # Since we need to print the first entry out different from the rest, we'll check size and adjust accordingly
    my @row = $sth->fetchrow_array;
    $filter = "host @row";

    while ( @row = $sth->fetchrow_array )
    {
      $filter .= "\nor host @row";
    }

    my $count = $sth->rows;
    $sth->finish;

    # Now let's fetch the fqdn for the sensor ID
    $sth = $dbh->prepare("SELECT fqdn FROM sensors WHERE id == '$sensor'") or die $dbh->errstr;
    $sth->execute() or die $dbh->errstr;
    my @fqdn = $sth->fetchrow_array;

    my $file = $options->{'bpffile'} . "-@fqdn";
    open $OUTFH, '>', $file or die "Could not open outfile for writing: $1\n";
    print $OUTFH "( $filter )\nor ( vlan and (\n$filter ) )";
    close $OUTFH;

    print "Writing out $count records to $file.\n" unless $options->{'quiet'};
  }

  # Now we'll scope and write out the generic file
  if(1)
  {
    my $filter;
    my $sth = $dbh->prepare("SELECT ip FROM hosts WHERE sensors IS NULL");
    $sth->execute() or die $dbh->errstr;

    # Since we need to print the first entry out different from the rest, we'll check size and adjust accordingly
    my @row = $sth->fetchrow_array;
    $filter = "host @row";

    while ( @row = $sth->fetchrow_array )
    {
      $filter .= "\nor host @row";
    }

    my $count = $sth->rows;
    $sth->finish;

    my $output = '';
    $output = "( $filter )\nor ( vlan and (\n$filter ) )" unless $count == 0;

    my $file = $options->{'bpffile'};
    open $OUTFH, '>', $file or die "Could not open outfile for writing: $1\n";
    print $OUTFH $output;
    close $OUTFH;

    print "Writing out $count records to $file.\n" unless $options->{'quiet'};
  }
  #return $count;
  return 1;
}

#####################
## sub: ValidateHost(hostip)
##      Checks the given IP address to see if it is valid IPv4
sub ValidateHost
{
  my $ip = shift or die;
  my $DEBUG = shift;

  print "Validating host: $ip\n" if $DEBUG >= 2;
  return (ip_is_ipv4($ip));
}
#####################
## sub:  DeleteHost( hash_ref suspicioushosts, hash_ref arguments )
##       Accepts the IP address and removes it from the database
##
sub DeleteHost
{
  my $dbh = shift or die;
  my $options = shift or die;

  my $query = 'DELETE FROM hosts';
  # Act on the list of IPs if we're given some 

  if ( scalar @{$options->{'host'}} == 1 )
  {
    $query .= " WHERE ip='@{$options->{'host'}}[0]'";
  }
  else
  {
    $query .= " WHERE ip='@{$options->{'host'}}[0]'";
    for (my $i=1; $i<scalar @{$options->{'host'}}; $i++ )
    {
      $query .= " or ip='@{$options->{'host'}}[$i]'";
     }
  }

  print 'DEBUG: Removing hosts: ' . join(", ",@{$options->{'host'}}) . "\n" if $options->{'verbose'}  >= 3;
  my $sth = $dbh->prepare($query);
  my $count = $sth->execute() or die $sth->errstr;
  $sth->finish;
  return ( ($count == '0E0') ? 0 : $count);
}

#####################
## sub:  ExpireEntries( hash_ref suspicioushosts, hash_ref arguments )
##       Process the tracking database and delete expired records
##
sub ExpireEntries
{
  my $dbh = shift or die;
  my $options = shift or die;

  my $time = time;

  my $sth = $dbh->prepare("DELETE FROM hosts WHERE ttl < '$time'");
  my $count = $sth->execute() or die $sth->errstr;

  print 'Expired ' . (($count == '0E0') ? 0 : $count) . " records.\n" unless $options->{'quiet'};

  return ( ($count == '0E0') ? 0 : $count);
}

#####################
## sub:  AddHost( hash_ref suspicioushosts, hash_ref arguments )
##       Accepts the IP and expiration time and adds it to the database
##
sub AddHost
{
  my $dbh = shift or die;
  my $options = shift or die;
  my $count = 0;

  # Normalize the time (given as TTL in minutes) to the expiration epoch
  my $time = (time + ( $options->{'time'} * 60 ));

  my $query;

  # Unfortunately we have to build out the SQL separately if we're binding hosts to a sensor
  if( exists($options->{'sensor'}) )
  {
    $query = "INSERT INTO hosts ('ip', 'ttl', 'sensors') SELECT '@{$options->{'host'}}[0]', '$time', '@{$options->{'sensor'}}' ";
    # Act on the list of IPs if we're given some 
    for (my $i=1; $i<scalar @{$options->{'host'}}; $i++ )
    {
      $query .= " UNION SELECT '@{$options->{'host'}}[$i]', '$time', '@{$options->{'sensor'}}' ";
    }
  }
  else
  {
    $query = "INSERT INTO hosts ('ip', 'ttl') SELECT '@{$options->{'host'}}[0]', '$time'";
    # Act on the list of IPs if we're given some 
    for (my $i=1; $i<scalar @{$options->{'host'}}; $i++ )
    {
      $query .= " UNION SELECT '@{$options->{'host'}}[$i]', '$time'";
    }
  }

  my $sth = $dbh->prepare($query);
  $count = $sth->execute() or die $sth->errstr;
  print 'DEBUG: Adding hosts: ' . join(", ",@{$options->{'host'}}) . " to ttl: " . scalar localtime($time) . "\n" if $options->{'verbose'} >= 3;
  $sth->finish;

  return ( ($count == '0E0') ? 0 : $count);
}
sub UpdateHost
{
  my $dbh = shift or die;
  my $options = shift or die;
  my $count = 0;

  # Normalize the time (given as TTL in minutes) to the expiration epoch
  my $time = (time + ( $options->{'time'} * 60 ));

  my $query = "UPDATE hosts SET ttl='$time'";
  # Act on the list of IPs if we're given some 
  if( exists($options->{'host'}) )
  {
    $query .= " WHERE ip='@{$options->{'host'}}[0]'";
    for (my $i=1; $i<scalar @{$options->{'host'}}; $i++ )
    {
      $query .= " or ip='@{$options->{'host'}}[$i]'";
    }
  }

  my $sth = $dbh->prepare($query);
  $count = $sth->execute() or die $sth->errstr;

  my $hosts =  (exists($options->{'host'})) ? join(", ",@{$options->{'host'}}) : 'all hosts';
  print 'DEBUG: Updated hosts: ' . $hosts . " to ttl: " . scalar localtime($time) . "\n" if $options->{'verbose'} >= 3;
  $sth->finish;

  return ( ($count == '0E0') ? 0 : $count);
}

#####################
## sub:  Print( hash_ref suspicioushosts, hostip )
##       Reads out the values from the database and prints them to the screen
##
sub Print
{
  my $dbh = shift or die;
  my $options = shift or die;

  my $query = 'SELECT ip,ttl FROM hosts';
  if( exists($options->{'host'}) )
  {
    if ( scalar @{$options->{'host'}} == 1 )
    {
      $query .= " WHERE ip='@{$options->{'host'}}[0]'";
    }
    else
    {
      $query .= " WHERE ip='@{$options->{'host'}}[0]'";
      for (my $i=1; $i<scalar @{$options->{'host'}}; $i++ )
      {
        $query .= " or ip='@{$options->{'host'}}[$i]'";
      }
    }
  }

  my $sth = $dbh->prepare($query);
  $sth->execute() or die $sth->errstr;

  my @row;
  print "Host Addr\tExpiration Date\n";
  while ( @row = $sth->fetchrow_array ) {
    print "$row[0]\t" . scalar localtime($row[1]). "\n";
  }

  $sth->finish;

  # No processing happens, so let's just always return true
  return 0;
}

1;

## Changelog ##
# eba323d -- Scott Pack (Wed Sep 19 16:36:57 2012 -0400) Collapsing multiple inserts into a single statement
# d5268ae -- Scott Pack (Wed Sep 19 14:04:16 2012 -0400) Moving ExpireHosts to database. Fixing return statements to account for 0E0 from DBI.
# 9b080c5 -- Scott Pack (Wed Sep 19 10:46:54 2012 -0400) Migrating UpdateHosts, AddHosts, Print, DeleteHost, and BuildBPF to operate on SQLite database
# f6293f5 -- Scott Pack (Wed Sep 12 16:24:26 2012 -0400) Migrating from yaml to sqlite. Partial migration commit
# f68741d -- Scott Pack (Sat Sep 8 16:03:16 2012 -0400) Updating documentation for update
# 41a37d8 -- Scott Pack (Sat Sep 8 15:59:52 2012 -0400) Adding support for updating all times at once
# 168f138 -- Scott Pack (Wed Aug 29 11:09:06 2012 -0400) Fixing build process to account for vlan tags existing or not
# 9bcd8a5 -- Scott Pack (Wed Jul 4 12:50:35 2012 -0400) Changing filehandle bareword in BuildBPF after warning from Perl::Critic
# b3e6850 -- Scott Pack (Thu Jun 21 15:00:14 2012 -0400) Converting Getopt to use options hash instead of raw variables.
