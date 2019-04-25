Name: Dror Pezo
E-mail: Drorpezo@campus.technion.ac.il
ID: 318689049

How to run the tool:
1) Copy ex1.cpp file to the directory:
/pin-3.7-97619-g0d0c92f4f-gcc-linux/source/tools/ManualExamples

2) Create empty output csv file 'rtn-output-tst.csv'

3) Create executable using make:
make ex1.test

4) Run the tool:
../../../pin -t obj-intel64/ex1.so -- <prog>
Where prog is the target program

5) Results should appear in 'rtn-output-tst.csv' file


