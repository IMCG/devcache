#!/usr/bin/perl

$usage = "usage: <file|loop|ram|real> <primary_dev|filename> [<blocksize> [iter_once]] ";

($TYPE=shift @ARGV) || die $usage;

$bbdev='';
if($TYPE=~/^(loop)|(ram)|(real)|(file)$/) {
	$bbdev='/dev/bb1' if($TYPE eq 'loop');
	$bbdev='/dev/bb0' if($TYPE eq 'ram');
	$bbdev='/dev/bb2' if($TYPE eq 'real');
#	$bbdev='/dev/bb2' if($TYPE eq 'real');
} else { die $usage; }

$oflags = '';
#$oflags = 'oflags=fsync';

$write_entire=0;

$SIZE=409600;
$Sk = $SIZE/1024;

($dev=shift @ARGV) || die $usage;
if($TYPE eq 'file')
{
	$bbdev=$dev;
}else{
$dev='/dev/'.$dev;
}
($bs=shift @ARGV) || ($bs=4096);
if($bs=~/^0x(.*)/) {
	$bs=hex($1);
}
#$bs=4096;
($once=shift @ARGV) || ($once=-1);
printf("once=$once\n");
printf("bbdev=$bbdev\n");
printf("dev=$dev\n");
printf("blocksize=%d\n",$bs);
print "creating rand file\n";
	`dd if=/dev/urandom of=rfile2 bs=1k count=$Sk`;

# clear backing
	print "clearing backing device\n";
	`dd if=/dev/urandom of=$dev bs=1k count=$Sk`;


# WRITE ENTIRE FILE
if($write_entire==1){
	print "writing entire file";
	`dd if=rfile2 of=$bbdev bs=1k count=$Sk $oflags`;
}

print "analyzing...\n";

$start = 0;
$max = $SIZE/$bs -1;
if($once != -1) { $start=$once; $max=$once; }
for($i=$start;$i<$max+1;$i++)
#for($i=$max;$i>=$start;$i--)
{
if($write_entire!=1) {
	# WRITE ONLY BLOCK
	`dd if=rfile2 of=$bbdev bs=$bs count=1 skip=$i seek=$i $oflags 2>/dev/null`;
	`sync`;
}
	$good = `dd if=rfile2 bs=$bs count=1 skip=$i 2>/dev/null | md5sum`;
	$exp = `dd if=$bbdev bs=$bs count=1 skip=$i 2>/dev/null | md5sum`;
	 $exp2 = `dd if=$dev bs=$bs count=1 skip=$i 2>/dev/null | md5sum`;
	#$exp2 = `dd if=$dev bs=$bs count=1 skip=$i 2>/dev/null | md5sum`;
	my $pf='';
	if($good eq $exp) { $pf.='read pass | '; } else {$pf.='READ FAIL | ';}
	if($good eq $exp2) { $pf.='write pass'; } else {$pf.='WRITE FAIL';}
	$base = $i*$bs;
	if($pf=~/FAIL/ || ($base&0xffff)==0)
	{	printf("0x%08x-0x%08x %04d %s\n",$base,$base+$bs, $i, $pf); }
}
