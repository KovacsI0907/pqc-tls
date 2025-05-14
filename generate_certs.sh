#!/bin/bash
set -e

CA_SUBJ="/C=US/ST=California/L=San Francisco/O=MyOrg/OU=SelfSignedCA/CN=MyRootCA"
LEAF_SUBJ="/C=US/ST=California/L=San Francisco/O=MyOrg/OU=WebServer/CN=www.example.com"
DAYS_CA=3650
DAYS_LEAF=825
KEY_SIZE=2048

# Filenames
CA_KEY=ca.key
CA_CERT=ca.crt
LEAF_KEY=pkey.pem
LEAF_CSR=leaf.csr
LEAF_CERT=leaf.crt
CHAIN_PEM=chain.pem

echo "1) Generating Root CA key..."
openssl genrsa -out "$CA_KEY" $KEY_SIZE

echo "2) Generating Root CA self-signed cert..."
openssl req -x509 -new -nodes \
  -key "$CA_KEY" \
  -days $DAYS_CA \
  -subj "$CA_SUBJ" \
  -out "$CA_CERT"

echo "3) Generating leaf private key..."
openssl genrsa -out "$LEAF_KEY" $KEY_SIZE

echo "4) Generating leaf CSR..."
openssl req -new \
  -key "$LEAF_KEY" \
  -subj "$LEAF_SUBJ" \
  -out "$LEAF_CSR"

echo "5) Signing leaf CSR with our Root CA..."
openssl x509 -req \
  -in "$LEAF_CSR" \
  -CA "$CA_CERT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -days $DAYS_LEAF \
  -out "$LEAF_CERT"

echo "6) Building chain.pem (leaf first, then CA)..."
cat "$LEAF_CERT" "$CA_CERT" > "$CHAIN_PEM"

echo
echo "Done."
echo "  - Leaf key:      $LEAF_KEY"
echo "  - Leaf cert:     $LEAF_CERT"
echo "  - CA key:        $CA_KEY"
echo "  - CA cert:       $CA_CERT"
echo "  - Chain bundle:  $CHAIN_PEM"
