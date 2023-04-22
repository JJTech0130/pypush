set -e
# Use brew's openssl
export PATH="/opt/homebrew/opt/openssl@3/bin:$PATH"

openssl req -newkey rsa:2048 -nodes -keyout root_key.pem -x509 -days 3650 -out root_certificate.pem \
    -subj "/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Root CA" \
    -addext "basicConstraints=critical, CA:true" -addext "keyUsage=critical, digitalSignature, keyCertSign, cRLSign"

openssl req -newkey rsa:2048 -nodes -keyout intermediate_key.pem -out intermediate_certificate.csr \
    -subj "/CN=Apple Server Authentication CA/OU=Certification Authority/O=Apple Inc./C=US" \
    -addext "basicConstraints=critical, CA:true" -addext "keyUsage=critical, keyCertSign, cRLSign"
    # Need 1.2.840.113635.100.6.2.12?

openssl x509 -req -CAkey root_key.pem -CA root_certificate.pem -days 3650 \
    -in intermediate_certificate.csr -out intermediate_certificate.pem -CAcreateserial -copy_extensions copyall

openssl req -newkey rsa:2048 -nodes -keyout push_key.pem -out push_certificate.csr \
    -subj "/CN=courier.push.apple.com/O=Apple Inc./ST=California/C=US" \
    -addext "basicConstraints=critical, CA:false" \
    -addext "subjectAltName = DNS:courier.push.apple.com, DNS:courier2.push.apple.com" \
    -addext "keyUsage = critical, digitalSignature, keyEncipherment" \
    -addext "extendedKeyUsage = serverAuth"

openssl x509 -req -CAkey intermediate_key.pem -CA intermediate_certificate.pem -days 365 \
    -in push_certificate.csr -out push_certificate.pem -CAcreateserial -copy_extensions copyall

cat push_certificate.pem intermediate_certificate.pem root_certificate.pem > push_certificate_chain.pem

# Remove the leftover files
rm intermediate_certificate.csr intermediate_certificate.pem intermediate_key.pem intermediate_certificate.srl
rm push_certificate.csr push_certificate.pem
rm root_certificate.pem root_key.pem root_certificate.srl