Name: Dror Pezo, Amnon Balanov
E-mail: Drorpezo@campus.technion.ac.il, Samnonb@campus.technion.ac.il
ID: 318689049, 200995645

How to run the tool:
1) Copy ex4.cpp file to the directory:
/pin-3.7-97619-g0d0c92f4f-gcc-linux/source/tools/ManualExamples
or:
/pin-3.7-97619-g0d0c92f4f-gcc-linux/source/tools/SimpleExamples

2) Create executable using make:
make ex4.test

3) Collect profile data:
../../../pin -t obj-intel64/ex4.so -prof -- ./bzip2 -k -f input.txt

4) Run pintool 'inst' command:
../../../pin -t obj-intel64/ex4.so -inst-- ./bzip2 -k -f input.txt



