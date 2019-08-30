Name: Dror Pezo, Amnon Balanov
E-mail: Drorpezo@campus.technion.ac.il, Samnonb@campus.technion.ac.il
ID: 

How to run the tool:
1) Copy project.cpp file to the directory:
/pin-3.7-97619-g0d0c92f4f-gcc-linux/source/tools/ManualExamples
or:
/pin-3.7-97619-g0d0c92f4f-gcc-linux/source/tools/SimpleExamples

2) Create executable using make:
make project.test

3) Collect profile data:
../../../pin -t obj-intel64/project.so -prof -- ./bzip2 -k -f long-input.txt

4) Run pintool 'inst' command:
../../../pin -t obj-intel64/project.so -opt <unrolling_lvl> -- ./bzip2 -k -f long-input.txt



