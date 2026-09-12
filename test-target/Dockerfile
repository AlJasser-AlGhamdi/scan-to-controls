FROM nginx:stable-alpine@sha256:0d3b80406a13a767339fbe2f41406d6c7da727ab89cf8fae399e81f780f814d1

RUN apk add --no-cache openssl \
 && mkdir -p /etc/nginx/tls \
 && cd /etc/nginx/tls \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout selfsigned2048.key -out selfsigned2048.crt -subj "/CN=test-target.local" 2>/dev/null \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout ca.key -out ca.crt -subj "/CN=Acme Internal Root" 2>/dev/null \
 && openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr \
      -subj "/CN=leaf.test-target.local" 2>/dev/null \
 && openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -out leaf.crt -days 3650 2>/dev/null \
 && openssl req -x509 -newkey rsa:1024 -nodes -days 3650 \
      -keyout rsa1024.key -out rsa1024.crt -subj "/CN=weak.test-target.local" 2>/dev/null \
 && openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
      -keyout rsa4096.key -out rsa4096.crt -subj "/CN=strong.test-target.local" 2>/dev/null \
 && openssl ecparam -name prime256v1 -genkey -noout -out ecp256.key \
 && openssl req -x509 -key ecp256.key -out ecp256.crt -days 3650 \
      -subj "/CN=ecp256.test-target.local" 2>/dev/null \
 && openssl ecparam -name prime192v1 -genkey -noout -out ecp192.key \
 && openssl req -x509 -key ecp192.key -out ecp192.crt -days 3650 \
      -subj "/CN=ecp192.test-target.local" 2>/dev/null \
 && openssl req -x509 -newkey rsa:2048 -nodes -not_before 20200101000000Z -not_after 20200102000000Z \
      -keyout expired.key -out expired.crt -subj "/CN=expired.test-target.local" 2>/dev/null \
 && rm -f leaf.csr ca.key

COPY default.conf /etc/nginx/conf.d/default.conf
