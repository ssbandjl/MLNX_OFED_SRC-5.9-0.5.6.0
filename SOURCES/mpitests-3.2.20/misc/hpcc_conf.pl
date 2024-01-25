#!/usr/bin/perl -w
use strict;
use Math::Complex;
use Getopt::Long;

sub Calc_NP
{
    my ($p,$q,$tail,$np)=@_;
    for(my $i=1;$i<=int(sqrt($np));$i++)
    {
        for(my $j=1;$j<=$np;$j++)
        {
            if($j*$i == $np)
            {
                push (@$p,$i);
                push (@$q,$j);
            }
        }
    }

    my $size = @$p;
    if ($size>=$tail) {
        @$p = reverse @$p;
        @$q = reverse @$q;
        delete @$p[$tail..$size];
        delete @$q[$tail..$size];
    }
}

sub Generate_HPL_DAT
{
    my ($Ns,$p,$q,$nb,$rfacts,$pfacts,$nbmins,$comment, $hpl)=@_;

    my $size;

    my $footer="##### This line (no. 32) is ignored (it serves as a separator). $comment ######
0                               Number of additional problem sizes for PTRANS
1200 10000 30000                values of N
0                               number of additional blocking sizes for PTRANS
40 9 8 13 13 20 16 32 64        values of NB
";

open HPL,">$hpl" or die "$!";
print HPL "HPLinpack benchmark input file\n" ;
print HPL "Innovative Computing Laboratory, University of Tennessee\n";
print HPL "HPL.out      output file name (if any)\n";
print HPL "6            device out (6=stdout,7=stderr,file)\n";
print HPL "1            # of problems sizes (N)\n";
print HPL "$Ns          Ns\n";
$size = @$nb;
print HPL "$size        # of NBs\n";
print HPL "@$nb         NBs\n";
print HPL "0            PMAP process mapping (0=Row-,1=Column-major)\n";
$size=@$p;
print HPL "$size        # of process grids (P x Q)\n";
print HPL "@$p          Ps\n";
print HPL "@$q          Qs\n";
print HPL "16.0         threshold\n";
$size=@$pfacts;
print HPL "$size        # of panel fact\n";
print HPL "@$pfacts     PFACTs (0=left, 1=Crout, 2=Right)\n";
$size=@$nbmins;
print HPL "$size        # of recursive stopping criterium\n";
print HPL "@$nbmins     NBMINs (>= 1)\n";
print HPL "1            # of panels in recursion\n";
print HPL "2            NDIVs\n";
$size=@$rfacts;
print HPL "$size        # of panel fact\n";
print HPL "@$rfacts     RFACTs (0=left, 1=Crout, 2=Right)\n";
print HPL "1            # of broadcast\n";
print HPL "0            BCASTs (0=1rg,1=1rM,2=2rg,3=2rM,4=Lng,5=LnM)\n";
print HPL "1            # of lookahead depth\n";
print HPL "0            DEPTHs (>=0)\n";
print HPL "2            SWAP (0=bin-exch,1=long,2=mix)\n";
print HPL "64           swapping threshold\n";
print HPL "0            L1 in (0=transposed,1=no-transposed) form\n";
print HPL "0            U  in (0=transposed,1=no-transposed) form\n";
print HPL "1            Equilibration (0=no,1=yes)\n" ;
print HPL "8            memory alignment in double (> 0)\n";
print HPL $footer;
close HPL;
return $hpl;
}

sub usage 
{
    my ($help) = @_;
    if ($help) {
        print "\nError: $help";
    }
    print "
    
    Usage: 

        $0 -out hpcc.dat -fop_per_cycle 8 -mem_percent 0.8 -mem_node 32 -ppn 16 -nodes 16 -cpu_mhz 2700 [-fast]

\n";
    if ($help) {
        exit 1;
    }
}

my $dat_file;
my $nodes;
my $opt_fast;
my $opt_help;
my $float_op_per_cycle=8;
my $percent_of_mem=0.8;
my $mem_node = 32;
my $ppn = 16;
my $mhz = 2700;
my $opt_pfacts = "0,1,2";
my $opt_rfacts = "0,1,2";
my $opt_nbmins = "2,4";
my $nb_list = "80,112,96,128,150,220";
my $pq_list = 1;
my $opt_v = 0;

GetOptions( 
    'out|output|o=s' =>\$dat_file,
    'fop_per_cycle=i' => \$float_op_per_cycle,
    'mem_percent=f' => \$percent_of_mem,
    'mem_node=i' => \$mem_node,
    'ppn=i' => \$ppn,
    'nb|nb_list=s' => \$nb_list,
    'nodes=i' => \$nodes,
    'cpu_mhz=i' => \$mhz,
    'pfacts=s' => \$opt_pfacts,
    'rfacts=s' => \$opt_rfacts,
    'nbmins=s' => \$opt_nbmins,
    'pq_list=i' => \$pq_list,
    'fast' => \$opt_fast,
    'h|help' => \$opt_help,
    'v' => \$opt_v,
) or usage("Incorrect usage!\n");

if ($opt_help) {
    usage();
    exit 0;
}

usage("No -mem_node specified") if !$mem_node;
usage("No -ppn specified")      if !$ppn;
usage("No -nodes specified")    if !$nodes;
usage("No -cpu_mhz specified")  if !$mhz;

$dat_file = "hpccinf$nodes.txt" if (!$dat_file);

if ($opt_fast) {
    $opt_pfacts = "2";
    $opt_rfacts = "2";
    $opt_nbmins = "4";
    $nb_list = "220";
}

my (@p,@q);
my @nb = split(/,/,$nb_list);
my @pfacts = split(/,/,$opt_pfacts);
my @rfacts = split(/,/,$opt_rfacts);
my @nbmins = split(/,/,$opt_nbmins);

my $np=$nodes*$ppn;
#sqrt((Memory Size in Gbytes * 1024 * 1024 * 1024 * Number of Nodes) /8) * 0.90 
my $ns=int($percent_of_mem*sqrt(($mem_node*1024*1024*1024*$nodes)/$float_op_per_cycle));
#print "NS=$ns\n";

my $ns_align = $ns/$nbmins[0];
$ns = int($ns_align * $nbmins[0]);
#print "NS2=$ns\n";

my $max_tflops=($mhz*$np*$float_op_per_cycle)/1000;

Calc_NP(\@p,\@q,$pq_list,$np);
print "NP=$np NS=$ns P='@p' Q='@q' NB='@nb' fop=$float_op_per_cycle mem_per_node=$mem_node percent_of_mem=$percent_of_mem nodes=$nodes mhz=$mhz max_tflops=$max_tflops
    out=$dat_file rpeak_tflops=$max_tflops\n" if $opt_v;

Generate_HPL_DAT($ns,\@p,\@q,\@nb,\@rfacts,\@pfacts,\@nbmins,"max_tflops=$max_tflops mhz=$mhz np=$np mem_per_node=$mem_node", $dat_file);

exit 0;



