#ifndef ENCLAVE_H
#define ENCLAVE_H
#include <openenclave/host.h>

class Enclave {
    private:
        // Private constructor to prevent instancing
        Enclave() {}

    public:
        // Don't forget to declare these two. You want to make sure they
        // are unacceptable otherwise you may accidentally get copies of
        // your singleton appearing.
        Enclave (Enclave const&) = delete;
        void operator=(Enclave const&) = delete;

        oe_enclave_t* enclave_ref;
        int enclave_ret;

        static Enclave& getInstance() {
            static Enclave instance;
            return instance;
        }

        oe_enclave_t* getEnclave() {
            return this->enclave_ref;
        }

        oe_enclave_t** getEnclaveRef() {
            return &(this->enclave_ref);
        }

};
#endif
