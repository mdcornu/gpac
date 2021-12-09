#!/bin/bash

# Example usage:
# env PATH=$PATH":/path/to/gpac" ./gpac_cenc_bench.sh ./cbcs_const.xml ./source.mp4
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <drm_file.xml> <source_file.mp4> [basename]"
    exit 1
fi

# check GPAC available
if ! command -v gpac &> /dev/null
then
    echo "No path to GPAC utility!"
    exit
fi

# set args
drm_file=$1
src_file=$2

# options
nb_runs=6
nb_ignore_runs=3

# if basename supplied prepend to filenames
if [ -z "$3" ]
then
    basename=""
else
    basename=$3-
fi

# create dir to store logs + tmp files
mkdir -p logs

tmp_file=logs/${basename}time.tmp
stderr_file=logs/${basename}errors.log

# remove GPAC cache
rm -rf ~/.gpac

# reset error logs if they already exist
echo "" > $stderr_file

# main loop to encrypt src file 'nb_runs' times and calculate average time to complete
# don't include the first 'nb_ignore_runs' results to allow for warmup and more stable results
i=1
total="0.0"
count=0

while [ $i -le $nb_runs ]
do
    printf '.'
    /usr/bin/time -f "%e" -o $tmp_file gpac -i $src_file @ cecrypt:cfile=$drm_file @ -o null 2>> $stderr_file
    if [ "$?" -ne 0 ]; then
	echo "Error during run $i - exiting"
	cat $stderr_file
	exit
    fi

    time=$(cat $tmp_file)

    # ignore first N runs to let warm up
    if [ "$i" -gt "$nb_ignore_runs" ]; then
	total=$(echo "$total + $time" | bc -l)
	count=$((count + 1))
    fi
    i=$((i + 1))
done

# clean up
rm $tmp_file

avg=$(echo $total / $count | bc -l)
printf 'Average encrypt time over last %u runs: %0.2fs\n' "$count" "$avg"
