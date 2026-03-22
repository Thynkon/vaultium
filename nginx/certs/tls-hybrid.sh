#!/bin/bash
set -e
set -x

root="root-ca"
web_server="nginx"

# Generate Root CA with ECDSA (required by rustls)
openssl ecparam -genkey -name prime256v1 -out data/hybrid/$root.key

openssl req -x509 -new -nodes \
  -key data/hybrid/$root.key \
  -out data/hybrid/$root.crt \
  -days 1825 \
  -config config/$root.cnf

openssl ecparam -genkey -name prime256v1 -out data/hybrid/$web_server.key

openssl req -new \
  -key data/hybrid/$web_server.key \
  -out data/hybrid/$web_server.csr \
  -config config/$web_server.cnf

openssl x509 -req \
  -in data/hybrid/$web_server.csr \
  -CA data/hybrid/$root.crt \
  -CAkey data/hybrid/$root.key \
  -CAcreateserial \
  -out data/hybrid/$web_server.crt \
  -days 365 \
  -extfile config/$web_server.cnf \
  -extensions server_reqext

# Verify
openssl verify -CAfile data/hybrid/$root.crt data/hybrid/$web_server.crt

rm data/hybrid/$web_server.csr
