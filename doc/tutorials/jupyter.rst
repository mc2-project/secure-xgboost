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

   A symmetric key is generated on the client to encrypt data.

2. **Data Encryption**
   
   The symmetric key is used to encrypt sensitive data.

3. **Enclave Preparation**
   
   An enclave is created, authenticated, and given the necessary keys.

4. **Data Loading**
   
   Encrypted data is loaded into the enclave. 

5. **Training**
   
   A model is securely trained inside the enclave.

6. **Prediction**
   
   The model yields encrypted predictions based off client test data, and the ciphertext is then decrypted.

Note that in the outsourced computation model, steps 1 and 2 are done on the client, and 3, 4, and 5 are done on the server. Inference resulting in encrypted predictions in step 6 happens on the server, and decryption of the encrypted predictions happens on the client.

