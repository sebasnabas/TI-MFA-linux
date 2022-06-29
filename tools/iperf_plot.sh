#!/usr/bin/env bash

pushd "$1" || exit 1

gnuplot > "iperf3_throughput_${2}.png" <<- EOF
    set term pngcairo
    set datafile sep " "
    # set key autotitle columnhead
    set xlabel "Time Slot (s)"
    set ylabel "Bandwidth (Mbit/s)"

    set yrange [0:*];
    set key right center inside
    set grid
    set style data lines

    plot "0_link_failures.dat" using 2:5 with linespoints pointtype 9 title "0 Link Failures", \
        "1_link_failure.dat" using 2:5 with linespoints pointtype 5 title "1 Link Failure", \
        "2_link_failures.dat" using 2:5 with linespoints pointtype 13 title "2 Link Failures"
EOF

popd || true
