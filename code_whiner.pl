#!/usr/bin/perl -w

use Perl::Critic;
my $file = shift;
my $critic = Perl::Critic->new(-theme => 'bugs || pbp || security', -include => ['layout'], -severity => 4);
my @violations = $critic->critique($file);
print @violations;
