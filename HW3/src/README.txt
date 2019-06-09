Name: Dror Pezo, Amnon Balanov
E-mail: Drorpezo@campus.technion.ac.il, Samnonb@campus.technion.ac.il
ID: 318689049, 200995645

How to run the tool:
1) Copy src folder to the directory:
/pin-3.7-97619-g0d0c92f4f-gcc-linux/source/tools

2) Create executable using make:
make ex3.test

3) Copy your program binary and input files to src folder
   (for example - bzip2 and input.txt), and provide them execution 
   permission with 'chmod +x <prog>' command.
4) Run the profiling tool:
../../../pin -t obj-intel64/ex3.so -prof -- <prog>
Where prog is the target program

5) Results should appear in 'loop-count.csv' file
6) Run the binary code generator tool:
../../../pin -t obj-intel64/ex3.so -inst -- <prog>
Where prog is the target program


