#!/usr/bin/env perl
#
# This software was written by Jim Fougeron jfoug AT cox dot net
# in 2015. No copyright is claimed, and the software is hereby
# placed in the public domain. In case this attempt to disclaim
# copyright and place the software in the public domain is deemed
# null and void, then the software is Copyright (c) 2015 Jim Fougeron
# and it is hereby released to the general public under the following
# terms:
#
# This software may be modified, redistributed, and used for any
# purpose, in source and binary forms, with or without modification.'
#
# dynamic_big_crypt_chopper.c.  This is a 'smart' sed like script.
# it will read command line, and all vars from command line should
# be in token=value format. Then the program will read all lines
# from stdin, and for all #{token} items found on the line, this
# will replace with appropriate value strings.
# Also, if token == DEFINED, then value is a CPP defined value, and
# we will parse code out properly in that way.  If token is UNDEFINED
# then we will know that this CPP value is NOT defined in our build.
#
# Ported to Perl at request of Magnum. We were seeing build/run issues
# on cross complier environments.

use warnings;
use strict;

if (@ARGV == 1 && $ARGV[0] eq "TEST" ) { exit 0; }

my %defined=(); my %tokens=(); my @define_stack=(1); my $nstack=1;

# load command line into the 2 hashes (one for defines and one for token replacements0
for (my $i = 0; $i < @ARGV; $i++) {
	foreach my $arg (@ARGV) {
		if (substr($arg,0,8) eq "DEFINED=")       { $defined{substr($arg,8)} = 'Y'; }
		elsif (substr($arg,0,10) eq "UNDEFINED=") { $defined{substr($arg,10)} = 'N'; }
		elsif ((my $pos = index($arg,'='))!=-1)   { $tokens{substr($arg,0,$pos)} = substr($arg,$pos+1); }
	}
}
#for my $d (keys %defined) { print "Is '$d' defined? $defined{$d}\n"; }
#for my $d (keys %tokens)  { print "value of '$d' is $tokens{$d}\n";  }
#exit(0);

print "\n/***********************************************************************\n";
print " * This section of the file auto-generated by dynamic_big_crypt_hash.cin\n";
print " * being run through dynamic_big_crypt_chopper.pl with this command line\n";
print " * ./dynamic_big_crypt_chopper.pl @ARGV\n";
print " ***********************************************************************/\n\n";

# now read stdin, and modify or drop each line, and write to stdout
foreach my $Line (<STDIN>) {
	chomp $Line;
	$Line = detok($Line);
	if ( in_defined($Line) ) { print "$Line\n"; }
}
exit(0);

# removes all the #{token} and replaces with value provided on command line
sub detok {
	my $Line = $_[0];
	my $pos = index($Line, "#{");
	if ($pos == -1) { return $Line; }
	while ($pos >= 0) {
		my $pos2 = index($Line, "}", $pos+1);
		my $tok = substr($Line,$pos+2,$pos2-$pos-2);
		substr($Line,$pos,$pos2-$pos+1) = $tokens{$tok};
		$pos = index($Line, "#{");
	}
	return $Line;
}

# tracks defined and undefined sections. If we are in an undefined section,
# we do not print.  If we are in a defined, then we do print.  the file
# always starts out in a defined state. Then defined and undefined sections
# get pushed and popped off the define stack. We also trim off special
# marking comments on #else or #endif that 'could' be cut, but that we do
# not have listed in our defined or undefined values.
sub in_defined {
	my $Line = $_[0];
	if (substr($Line,0,7) eq "#ifdef ") {
		# ok, see if this is one of our defines, or UNDEFINES.
		my $ch = $defined{substr($Line,7)};
		if (defined($ch) && $ch eq 'Y') {
			$define_stack[$nstack++] = 1;
			return 0;
		}
		if (defined($ch) && $ch eq 'N') {
			$define_stack[$nstack++] = 0;
			return 0;
		}
	} elsif (substr($Line,0,8) eq "#ifndef ") {
		# ok, see if this is one of our defines, or UNDEFINES.
		my $ch = $defined{substr($Line,8)};
		if (defined($ch) && $ch eq 'N') {
			$define_stack[$nstack++] = 1;
			return 0;
		}
		if (defined($ch) && $ch eq 'Y') {
			$define_stack[$nstack++] = 0;
			return 0;
		}
	} elsif (substr($Line,0,10) eq "#else  // ") {
		# this one may be the else statement for something defined or undefined.
		my $pos = index($Line, " defined ");
		if ($pos != -1) {
			my $ch = $defined{substr($Line,$pos+9)};
			$_[0] = substr($Line,0,5);
			if (defined($ch) && $ch eq 'Y') {
				$define_stack[$nstack-1] = 0;
				return 0;
			}
			if (defined($ch) && $ch eq 'N') {
				$define_stack[$nstack-1] = 1;
				return 0;
			}
		}
		# this is the else for #ifndef
		$pos = index($Line, " !defined ");
		if ($pos != -1) {
			my $ch = $defined{substr($Line,$pos+10)};
			$_[0] = substr($Line,0,5);
			if (defined($ch) && $ch eq 'N') {
				$define_stack[$nstack-1] = 0;
				return 0;
			}
			if (defined($ch) && $ch eq 'Y') {
				$define_stack[$nstack-1] = 1;
				return 0;
			}
		}
	} elsif (substr($Line,0,11) eq "#endif  // ") {
		# this one may be the endif statement for something defined or undefined.
		my $pos = index($Line, "defined ");
		if ($pos != -1) {
			my $ch = $defined{substr($Line,$pos+8)};
			$_[0] = substr($Line,0,6);
			if (defined($ch) && ($ch eq 'Y' || $ch eq 'N')) {
				--$nstack;
				return 0;
			}
		}
	}
	# if there are ANY undefined items in the stack, then we ARE undefined
	for (my $x = $nstack-1; $x >= 0; --$x) {
		if ($define_stack[$x] == 0) {return 0;}
	}
	return $define_stack[$nstack-1];
}
