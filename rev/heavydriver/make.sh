git clone https://github.com/aunali1/super-strip.git;
cd super-strip;
make;
mv sstrip /usr/bin/;
cd ..;
gcc -static -no-pie -O3 -funroll-loops heavydriver.c -o heavydriver;
python packer.py heavydriver;
mv heavydriver.packed heavydriver;
sstrip heavydriver;
printf'\x02'| dd conv=notrunc of=./heavydriver bs=1 seek=5;
