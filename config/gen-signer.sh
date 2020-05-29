# Helper script to generate keys + certificate for the trusted authority (signer)
# The authority signs the enclave binary, and also acts as the CA for signing client identities

# Generate keypair for signer
openssl genrsa -out signer.pem -3 3072
openssl rsa -in signer.pem -pubout -out signer.pub

# Generate self-signed root certificate
openssl req -x509 -new -nodes -key signer.pem -sha256 -days 365 -out signer.crt -subj "/CN=root"
