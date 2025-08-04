#!/bin/bash
#
# Functions
function onearg() {
#
# Script must have at least ones arguement which is file to parse
#
if [ "$1" = "" ]
then
	echo "[-] Usage $0 <some file>"
	exit
fi
}
usetestfile() {
filename=/home/ubuntu/IOC/query_45.txt
}
queryip() {
# This function queries the IP using greynoise's python class, send the output to an outfile for parsing
echo "[-] Running greynoise query on $targetip"
greynoise query $targetip > greynoise_query_$targetip.txt
filename="greynoise_query_$targetip.txt"
#testfile=/home/ubuntu/IOC/query_45.txt
#filename=$testfile
echo "[-] Filename set as $filename"
noresults=$(grep -c "No results found for this query" $filename)
benigntarget=$(grep -c "Benign" $filename)
}
countdestcountries() {
# This function counts the unique destination countries which factors into robust/rare score
totaldc=$(cat $filename | grep Destination | tr ',' '\n' | wc -l)
echo "[-] Total dest countries = $totaldc"
}
countdestports() {
# This function counts the number of ports and factors into robustness or rarity
totalports=$(cat $filename | grep "Port/Proto" | wc -l)
echo "[-] Total ports = $totalports"
}
countcve() {
totalcve=$(cat $filename | grep "CVE:" | wc -l)
echo "[-] Total CVE is $totalcve"
}
getepoch() {
# This function get the current date, first seen and Last seen to make inference of the persistence of the IOC
now=$(date +%s)
firstseen=$(cat $filename | grep "First seen" | awk -F' ' '{print $3}' | head -n 1 | xargs date +%s -d) 
lastseen=$(cat  $filename | grep "Last seen" | awk -F' ' '{print $3}' | head -n 1 | xargs date +%s -d)
activetime=$(( ($lastseen - $firstseen)/86400 ))
recentness=$(( ($now - $lastseen)/86400 ))
# This if clause prevents division by 0
if [ $recentness = "0" ]
then
	recentness="1"
fi
# Greytime is a combination of how long the IP has been active, along with how recent
# If active time and recent time are relatively the same, the division makes it 0 and recent time is the main factor
#
greytime=$(( ($activetime * $recentness) ))
#echo "[-] Time of analysis (now) is $now"
#echo "[-] First seen is $firstseen "
#echo "[-] Last seen is $lastseen"
#echo "[-] Active Time is $activetime "
#echo "[-] Recentness is $recentness"
echo "[-] Greytime is $greytime"
}
gettimestamp() {
rightnow=$(date +%Y_%m_%d_%H_%M)
echo "[-] Timehack is $rightnow"
}
makeoutfile() {
outfile=$(echo "greynoise_$file2parse_$rightnow")
#echo "ipaddr,totalCVE,totalDestCountries,totalPorts,recentTime,activeTime" > $outfile
echo "[-] $rightnow - Outfile set as $outfile"
}
#usetestfile
#onearg
logfile="/home/ubuntu/IOC/GreyNoiseQuad/Historical/greynoise_history.log"
gettimestamp
file2parse="/tmp/greytargets.txt"
find /tmp -maxdepth 1 -mtime -1 -type f -name "*.csv" -exec cat {} \; > $file2parse
if [ -s "$file2parse" ];
then
	echo "[-] $rightnow - Found file to parse = $file2parse" >> $logfile
	makeoutfile
else
	echo "[-] $rightnow There is no file to parse - exiting" >> $logfile
	rm $file2parse
	exit 1
fi
for targetip in $(cat $file2parse)
do
	queryip
	if [ $noresults = "1" ];
	then
		echo "[-] No results found for $targetip" >> $logfile
		sleep 1
		rm $filename
	else
		# Loop to remove benign results
		if [ $benigntarget = "0" ];
		then
			getepoch
			countcve
			countdestcountries
			countdestports
			greyfocus=$(( $totaldc + $totalcve + $totalports ))
			echo "[-] Greyfocus is $greyfocus"
			rm $filename
			echo "$targetip,$totalcve,$totaldc,$totalports,$recentness,$activetime,$greytime,$greyfocus" >> $outfile
		else
			echo "[-] This is a benign target, no results to the outfile from $targetip"
		fi
	fi
done
echo "[-] Greynoise quad complete, opening $outfile at time $rightnow"
cat $outfile
cp $outfile /home/ubuntu/greynoise.csv
mv $outfile /home/ubuntu/IOC/GreyNoiseQuad/Historical/
exit
