#!/usr/bin/perl
# File    : snuffler_managehost.pl
# Author  : Scott Pack
# Created : June 2012
# Purpose : Takes a list of IP address for network devices and 
#           adds them to the suspicious hosts tracker for
#           extra snort monitoring.
#
#     Copyright (c) 2012 Scott Pack. All rights reserved.
#     This program is free software; you can redistribute it and/or
#     modify it under the same terms as Perl itself.
#
#
#
use strict;
use warnings;
use feature "switch"; # Enables switch replacements given/when
use Getopt::Long qw(:config bundling);
use Pod::Usage;
use DBI;
#use Net::Snuffler;
use Snuffler;

my $version = '0.4';
my @validmodes = qw( add delete update expire print build create );

# Hash to store all of the command line arguments, along with defaults
my $options = { file => 'suspicious_hosts.db',
                time => '120',
                verbose => 0,
              };

# If first option doesn't have a hyphen then we're being given a run mode
$options->{'mode'} = shift(@ARGV) if( ! ( $ARGV[0] =~ /^-/ ) );

# Grab the options passed on the command line. 
GetOptions( $options,
    'time|t=i',         # numeric
    'file|f=s',         # string
    'host|ip|i=s@',     # string
    'bpffile|b=s',      # string 
    'sensor|s=s@',      # string
    'verbose|v+',       # flag
    'quiet|q',          # flag
    'version|V' => sub { printversion($version) },
    'help|?|h' => sub { pod2usage(1); },    # flag
) or pod2usage("$0: Unrecognized program argument.");


# Deep debugging code to dump out all the selected options
if( $options->{'verbose'} >= 4 )
{
  print "Processing based on following program settings:\n";
  while( my ($key, $value) = each %$options )
  {
    if( ref($value) eq "ARRAY" )
    {
      @$value = split(/,/,join(',',@$value));
      print "$key\t@$value\n";
    }
    else
    {
      print "$key\t$value\n";
    }
  }
}


# Argument sanity checks are run in 4 parts for simplicity of logic. 
# Part 1: Do we have a valid subcommand
ValidateMode($options);

# Part 2: Do we have the required information where applicable
ValidateOptions($options);

# Part 3: Input validation for IP addresses
if( exists($options->{'host'}) )
{
  @{$options->{'host'}} = split(/,/,join(',',@{$options->{'host'}}));

  foreach my $host (@{ $options->{'host'} })
  {
    ValidateHost($host, $options->{'verbose'}) or die "Not an IPv4 address: $host. Please validate your own input.\n";
  }
}

my $dbh = DBI->connect("dbi:SQLite:dbname=$options->{'file'}","","");
die "Failed to open database: $DBI::errstr" if !(defined $dbh);

ValidateDB($dbh, $options) or die "Table structure not sound. Create the table or fix the glitch.\n" unless $options->{'mode'} =~ 'create';

# Part 4: Input validation for Sensor IDs
if( exists($options->{'sensor'}) )
{
  if( ValidateSensor($dbh, $options) != 0 ) { die "Invalid sensors requested.\n"; }
}

# Now that all of our input validation has happened, let's do some work.
given ( $options->{'mode'} )
{
  when (/^print/) { Print($dbh, $options) }
  when (/^delete/) { DeleteHost($dbh, $options) }
  when (/^expire/) { ExpireEntries($dbh, $options) }
  when (/^build/) { BuildBPF($dbh, $options) }
  when (/^add/) { AddHost($dbh, $options) }
  when (/^update/) { UpdateHost($dbh, $options) }
  when (/^create/) { CreateDB($dbh, $options) }
  default { pod2usage("$0: Invalid mode: $options->{'mode'}") }
}

########################
# SUBROUTINES BABY!!
########################

sub ValidateDB
{
  my $dbh = shift or die;
  my $options = shift or die;

  my $correct_db_structure = {
    hosts => ['ttl', 'ip', 'sensors'],
    sensors => [ 'id', 'fqdn'],
    sqlite_master => [ 'rootpage', 'sql', 'name', 'type', 'tbl_name'],
  };

  # Let's get all the table names
  my $sth = $dbh->table_info( '', 'main', '%' );
  my $tableinfo = $sth->fetchall_hashref('TABLE_NAME');

  # For speed we'll check that each table exists and is correctly formed in one pass
  foreach my $tablename (keys %$tableinfo )
  {
    if ( ! exists $correct_db_structure->{$tablename} )
    {
      print "Database Schema Error: Detected missing tables. Please repair or initialize.\n";
      exit 1;
    }

    # Let's work on enumerating the table layouts and see if they match what we expect.
    my $sth = $dbh->column_info( '', 'main', $tablename, '%' );
    my $column_info = $sth->fetchall_hashref('COLUMN_NAME');
    my @column_names = sort keys %$column_info ;
    my @expected_names = sort @{$correct_db_structure->{$tablename}};

    if ( ! &array_compare( \@column_names, \@expected_names ) )
    {
      print "Database Schema Error: Malformed table '$tablename'. Please repair or initialize.\n";
      exit 1;
    }
  }

  print "Table structure recognized.\n" if $options->{'verbose'} >= 3;
  return 1;
}

sub ValidateSensor
{
  my $dbh = shift or die;
  my $options = shift or die;
  my $DEBUG = shift;

  my $filter = 'id == "' . join('" or id == "',@{$options->{'sensor'}}) . '"';

  my $sth = $dbh->prepare("SELECT id,fqdn from sensors where $filter");
  $sth->execute() or die $dbh->errstr;

  my $retval = $sth->fetchall_hashref('id');

  my $failures = 0;
  foreach my $sensorid (@{ $options->{'sensor'} })
  {
    next if exists($retval->{$sensorid});
    print "ERR: Invalid Sensor ID: $sensorid\n";
    $failures++;
  }

  return($failures);
}

sub CreateDB
{
  my $dbh = shift or die;
  my $options = shift or die;

  my $sth = $dbh->prepare('CREATE TABLE IF NOT EXISTS hosts (ip, ttl, sensors)');
  $sth->execute() or die $sth->errstr;
  $sth->finish;

  return 1;
}

sub array_compare {
    my ($first, $second, @comp) = @_;
    return 0 if @{$first} != @{$second};
    @comp = grep {$first->[$_] ne $second->[$_]} 0..$#$first;
    return not @comp;
}

sub ValidateMode
{
  my $options = shift;

  if( ! exists($options->{'mode'}) )
  {
    pod2usage("$0: Run mode required");
  }

  if( !( $options->{'mode'} ~~ @validmodes ) )
  {
    pod2usage("$0: Invalid mode: $options->{'mode'}");
  }

  return 1;
}

sub ValidateOptions
{
  my $options = shift;

  # Adding or Deleting requires specifying at least one IP
  if(  !(exists($options->{'host'})) && ($options->{'mode'} =~ /(add)|(delete)/) )
  {
    pod2usage("$0: Subcommand $options->{'mode'} requires IP address(es).");
  }
  elsif( !(exists($options->{'bpffile'})) && ($options->{'mode'} =~ /(build)/) )
  {
    pod2usage("$0: Subcommand $options->{'mode'} requires ouput file for filters.");
  }
  elsif( !( -e $options->{'file'}) && ($options->{'mode'} =~ /(delete)|(update)|(expire)|(print)|(build)/ ) )
  {
    die "Requested action requires existing host tracking database! File Not Found: $options->{'file'}\n";
  }

  return 1;
}

sub printversion
{
  my $version = shift;

  print "snuffler_managehost.pl $version\n";
  print "Copyright (c) 2012 Scott Pack. All rights reserved.\n";
  print "This program is released under Creative Commons Attribution-NonCommercial-NoDerivs 3.0 United States License <http://creativecommons.org/licenses/by-nc-nd/3.0/us/>.\n";

  exit 1;
}
__END__

=head1 NAME

snuffler_managehost.pl - Manages the suspicious host tracking database used by Snuffler for more thorough snort monitoring.

=head1 DESCRIPTION

This is the management utility for the Snuffler addon to the Snort IDS. It manages the suspicious host tracking database 
and generates the BPF file used by Snuffler.

=head1 SYNOPSIS

 snuffler_managehost.pl <subcommand> [options]

 Available subcommands:
   add              Add entries to the database.
   delete           Remove entries from the database.
   update           Update expiration times on existing entries.
   expire           Process database and remove any entries that have expired.
   build            Process the database and create a BPF file.
   print            Displays the entries and expiration times.
   create           Create the database structure if blank.

 Options:
   -f, --file       sqlite file to store/retrieve host information
   -i, --ip         The IP address to operate on
   -t, --time       Specify TTL in minutes for monitored hosts (default: 120)
   -b, --bpffile    File to save the BPF output filters to
   -v, --verbose    Be chattier with process output
   -q, --quiet      Only print essential messages
   -h, --help       Brief help message (this one)

=head1 SUBCOMMANDS

=over 8

=item B<add>

Inserts new entries into the database. Requires at least one IP address.

=item B<delete>

Immediately removes entries from the databse. This is primarily used to remote
hosts prior to their expiration time. Requires at least one IP address.

=item B<update>

Updates the expiration time on an existing IP address as if it were newly added.
Unlike the add routine this requires the tracking database already exists. If can
alternatively be used without specifying an address to update all entries.

=item B<expire>

Find all entries in the database that have passed their expiration time and remove
them. 

=item B<build>

Process the database and create a Berkeley Packet Filter format file that will match any of the
hosts in the database. Prior to generating the file it will perform an expiration.

=item B<print>

Prints out the database in a friendly format. If IP address are given, then only those hosts are displayed. Otherwise
all hosts within the database are printed.

=item B<create>

Should only be used if the tracking database is uninitialized. This creates the table structure.

=back

=head1 OPTIONS

=over 8

=item B<-f,--file>

Full path to file that contains the suspicious hosts tracking database. Default to: ./suspicious_hosts.yml

=item B<-i,--ip>

IP address that is operated on by the subcommand. Can accept a comma separated list of addresses or be given multiple times.

=item B<-t,--time>

Expiration lifetime, in minutes, for the entry in tracking database. Defaults to 120

=item B<-s,--sensor>

Limits monitoring of the given IP address(es) to the specified sensor. Can accept a comma separated list of sensors or be given multiple times.

=item B<-b,--bpffile>

Full path to the output file for the generated BPFs.

=item B<-v,--verbose>

Be louder with output. Can be given multiple times.

=item B<-q,--quiet>

Suppress all normal and verbose output. Only display errors.

=item B<-h,--help>

Print a brief help message and exits.

=back

=head1 AUTHOR

Scott Pack - L<http://www.google.com/profiles/scott.pack/>

=head1 LICENSE

Copyright (c) 2012 Scott Pack. All rights reserved.
This program is released under Creative Commons Attribution-NonCommercial-NoDerivs 3.0 United States License L<http://creativecommons.org/licenses/by-nc-nd/3.0/us/>.

=cut

## Changelog ##
# 439b6fc -- Scott Pack (Wed Oct 24 16:08:10 2012 -0400) Some cleanup based on Perl::Critic advice
# 3759488 -- Scott Pack (Wed Oct 24 15:32:50 2012 -0400) Rewrite of ValidateDB subroutine. Now actually validates table structure.
# 0eb8511 -- Scott Pack (Wed Oct 24 15:19:15 2012 -0400) Removing references to yaml and adding help line for db creation
# dc52a43 -- Scott Pack (Wed Sep 19 16:35:54 2012 -0400) Adding support for validating db structure and creating the db
# fae87e5 -- Scott Pack (Wed Sep 19 10:46:02 2012 -0400) Separating out Add and Update subcommands to call proper subroutine
# f6293f5 -- Scott Pack (Wed Sep 12 16:24:26 2012 -0400) Migrating from yaml to sqlite. Partial migration commit
# 3fe5fd2 -- Scott Pack (Sat Sep 8 15:47:25 2012 -0400) Cleanup for PerlCritic and PBP. Moved input validation to subroutines for readability purposes.
# cf0283c -- Scott Pack (Wed Jul 4 12:42:55 2012 -0400) Fixing up documentation and adding additional POD sections.
# 1d32bf3 -- Scott Pack (Wed Jul 4 11:39:00 2012 -0400) Major cleanup. Moved subcommand detection from else/ifs to given/when. Tidied up input validation checks.
# 10ec41d -- Scott Pack (Fri Jun 29 16:54:27 2012 -0400) Moving buildbpf function as subcommand to managehost
# 2ebeaf5 -- Scott Pack (Wed Jun 27 12:03:15 2012 -0400) Migrated to using subcommands for operations instead of arguments
# b3e6850 -- Scott Pack (Thu Jun 21 15:00:14 2012 -0400) Converting Getopt to use options hash instead of raw variables.
# 8139a0b -- Scott Pack (Wed Jun 13 15:30:32 2012 -0400) Moving management subroutines to Snuffler module
# d30754c -- Scott Pack (Wed Jun 13 12:18:01 2012 -0400) Adding expiration routine to managehost
# 64b9926 -- Scott Pack (Wed Jun 6 16:11:59 2012 -0400) Adding IPv4 input validation. Option to update times for existing hosts.
# a6fcc35 -- Scott Pack (Wed Jun 6 15:29:12 2012 -0400) Add support to print out entry for specific IP, added default expiration time
# f2ad7e3 -- Scott Pack (Wed Jun 6 09:54:17 2012 -0400) Basic add/delete/print functionality added. Basic testing completed.
# 075188b -- Scott Pack (Wed Jun 6 09:54:17 2012 -0400) Initial checkin
