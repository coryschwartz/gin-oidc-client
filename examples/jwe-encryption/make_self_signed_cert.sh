#!/bin/bash

# Generate a private key
openssl genrsa -out private.key 2048

# Generate a certificate signing request (CSR)
openssl req -new -key private.key -out cert.csr -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com"

# Generate a self-signed certificate
openssl x509 -req -days 365 -in cert.csr -signkey private.key -out cert.pem

# Clean up the CSR
rm cert.csr

echo "Self-signed certificate and private key have been created:"
echo "  Certificate: cert.pem"
echo "  Private Key: private.key"
