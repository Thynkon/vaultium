#!/bin/bash
set -e
set -x

root="root-ca"
web_server="nginx"

openssl req -x509 -new -nodes \
  -newkey falcon1024 \
  -provider base \
  -provider default \
  -provider oqsprovider \
  -provider-path ./oqs-provider/_build/lib \
  -keyout data/full-pq/$root.key \
  -out data/full-pq/$root.crt \
  -days 1825 \
  -config config/$root.cnf

openssl genpkey \
  -algorithm falcon1024 \
  -provider base \
  -provider default \
  -provider oqsprovider \
  -provider-path ./oqs-provider/_build/lib \
  -out data/full-pq/$web_server.key

openssl req -new \
  -key data/full-pq/$web_server.key \
  -out data/full-pq/$web_server.csr \
  -config config/$web_server.cnf

openssl x509 -req \
  -in data/full-pq/$web_server.csr \
  -CA data/full-pq/$root.crt \
  -CAkey data/full-pq/$root.key \
  -CAcreateserial \
  -out data/full-pq/$web_server.crt \
  -days 365 \
  -extfile config/$web_server.cnf \
  -extensions server_reqext \
  -provider base \
  -provider default \
  -provider oqsprovider \
  -provider-path ./oqs-provider/_build/lib
