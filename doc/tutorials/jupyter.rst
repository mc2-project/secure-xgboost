#########################
Secure XGBoost in Jupyter
#########################

Secure XGBoost comes with a demo Jupyter notebook that provides some insight into how one can use the library. The notebook gives an end to end demo of a complete workflow. A practical use case of Secure XGBoost would involve outsourced computation requiring at least two machines (a client who owns the data and a server where computation on the data is done), but the workflow in the notebook has been simplified to require only one machine.

The notebook is located at ``demo/python/jupyter/e2e-demo.ipynb``.

**********************
An End to End Workflow
**********************

There are six main steps in the notebook:

1. **Key Generation**

   The client generates a secret symmetric key.

2. **Data Encryption**

   The client uses the key to encrypt its data.

3. ** User Initialization**

   The client creates a user object and passes in the path to its secret symmetric key, its private key, and its certificate.

4. **Enclave Preparation**
   
   The server creates an enclave, and starts a process within it. The client [*attests*](https://software.intel.com/en-us/articles/code-sample-intel-software-guard-extensions-remote-attestation-end-to-end-example) the enclave process, and securely transfers its key to the enclave.

5. **Data Loading**
   
   The enclave loads the client's encrypted data.

6. **Training**
   
   The enclave trains a model using the provided data.

7. **Prediction**
   
   The enclave makes predictions with the model, and produces a set of encrypted results; the client decrypts the results.

Note that in the outsourced computation model, steps 1, 2, and 3 are done on the client, and 4, 5, and 6 are done on the server. Inference yielding encrypted predictions in step 7 happens on the server, and decryption of the encrypted predictions happens on the client.

