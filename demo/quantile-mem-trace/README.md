
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
This will auto generate files `arr_A.h` and `arr_B.h` containing random arrays, and then build the programs `test_A.cc` and `test_B.cc`.

**src/common/quantile.h should be replaced by src/common/pin_quantile.h** 

**because logging and Macro would effect compile and memtrace.**

    ./make.sh

#### Execute the tests and capture memory trace
    ./profile_script.sh

#### Compare memory traces
Compare the memory traces captured during the runs. Trace files `test_A` and `test_B` traces should show no difference between them.

    diff test_A.trace test_B.trace

Repeat the steps to run the tests with different random inputs.
