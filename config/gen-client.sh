# Set client's name
if [ "$#" -ne 1 ]; then
    echo "Usage: ./gen-client.sh <username>"
    exit 1
fi
USERNAME=$1

# Generate keypair for client
echo "Generating keypair"
openssl genrsa -out ${USERNAME}.pem -3 3072

# Generate a certificate signing request
echo "Generating CSR"
openssl req -new -key ${USERNAME}.pem -out ${USERNAME}.csr -subj "/CN=${USERNAME}"

# Generate a certificate for the client signed by the signer
echo "Signing CSR"
openssl x509 -req -in ${USERNAME}.csr -CA signer.crt -CAkey signer.pem -CAcreateserial -out ${USERNAME}.crt

rm ${USERNAME}.csr
rm *.srl
