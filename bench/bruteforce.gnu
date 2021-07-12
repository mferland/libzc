set title "bruteforce (noradi.zip)"
set xrange [] reverse
set logscale y 2
set ytics add ("18.2" 18.2)
set grid y
set xlabel 'version'
set ylabel 'time (s)'
set style data histogram
set style histogram cluster gap 3
set style fill solid border -1
set xtic rotate by -45 scale 0
set key autotitle columnhead outside bottom center
set terminal png enhanced size 1000,800
plot 'results.txt' using 2:xticlabel(1), '' using 3, '' using 4, '' using 5, '' using 6, 18.2 title "fcrackzip on Core i7 950 @ 3.07GHz"
