
## Setup

#### Install Intel Pin
Download the software

    wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.11-97998-g7ecce2dac-gcc-linux.tar.gz
    cp pin-3.11-97998-g7ecce2dac-gcc-linux.tar.gz ~
    cd ~
    tar -zxvf pin-3.11-97998-g7ecce2dac-gcc-linux.tar.gz 
    ln -s ~/pin-3.11-97998-g7ecce2dac-gcc-linux ~/pin-dir

Set environment variable

    export PIN_ROOT=~/pin-dir

Build Intel Pin

    cd $PIN_ROOT/source/tools
    make all

#### Disable ASLR

    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

## Run the tests

#### Build the source files
This will auto generate files `arr_A.h` and `arr_B.h` containing random arrays, and then build the programs `sort_A.cc` and `sort_B.cc`.

    ./make.sh

#### Execute the tests and capture memory trace
This will run both programs twice -- once using `std::sort` and once using our `ObliviousSort` routine. While running the programs, it will also capture memory traces during each run.

    ./profile_sorts.sh

#### Compare memory traces
Compare the memory traces captured during the runs. Trace files `o_sort_A` and `o_sort_B` are the traces when the programs use `ObliviousSort`. Trace files `std_sort_A` and `std_sort_B` are traces captured when the programs use `std::sort`. Comparing the oblivious traces should show no difference between them, unlike the standard sort traces.

    diff o_sort_A.trace o_sort_B.trace
    diff std_sort_A.trace std_sort_B.trace

Repeat the steps to run the tests with different random inputs.
