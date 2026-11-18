FROM nginx:stable-alpine@sha256:0d3b80406a13a767339fbe2f41406d6c7da727ab89cf8fae399e81f780f814d1

RUN apk add --no-cache openssl \
 && mkdir -p /etc/nginx/tls \
 && cd /etc/nginx/tls \
 && openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
      -keyout selfsigned.key -out selfsigned.crt -subj "/CN=test-target.local" 2>/dev/null \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout ca.key -out ca.crt -subj "/CN=Acme Internal Root" 2>/dev/null \
 && openssl req -newkey rsa:3072 -nodes -keyout leaf.key -out leaf.csr \
      -subj "/CN=leaf.test-target.local" 2>/dev/null \
 && openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -out leaf.crt -days 3650 2>/dev/null \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout rsa2048.key -out rsa2048.crt -subj "/CN=weak.test-target.local" 2>/dev/null \
 && openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
      -keyout rsa4096.key -out rsa4096.crt -subj "/CN=strong.test-target.local" 2>/dev/null \
 && openssl ecparam -name prime256v1 -genkey -noout -out ecp256.key \
 && openssl req -x509 -key ecp256.key -out ecp256.crt -days 3650 \
      -subj "/CN=ecp256.test-target.local" 2>/dev/null \
 && openssl ecparam -name prime192v1 -genkey -noout -out ecp192.key \
 && openssl req -x509 -key ecp192.key -out ecp192.crt -days 3650 \
      -subj "/CN=ecp192.test-target.local" 2>/dev/null \
 && openssl req -x509 -newkey rsa:3072 -nodes -not_before 20200101000000Z -not_after 20200102000000Z \
      -keyout expired.key -out expired.crt -subj "/CN=expired.test-target.local" 2>/dev/null \
 && rm -f leaf.csr ca.key

RUN mkdir -p /srv/matrix/listing/docs /srv/matrix/login/admin /srv/matrix/search \
      /srv/matrix/sens/git/.git /srv/matrix/sens/env /srv/matrix/sens/dsstore /srv/matrix/sens/sql \
      /srv/matrix/sens/status /srv/matrix/sens/phpinfo \
 && printf 'quarterly report\n' > /srv/matrix/listing/report.txt \
 && printf 'ref: refs/heads/main\n' > /srv/matrix/sens/git/.git/HEAD \
 && printf 'APP_KEY=base64:matrix-only\nDB_PASSWORD=matrix-only\n' > /srv/matrix/sens/env/.env \
 && printf '\000\000\000\001Bud1\000\000' > /srv/matrix/sens/dsstore/.DS_Store \
 && printf -- '-- MySQL dump 10.13\nCREATE TABLE t (id int);\n' > /srv/matrix/sens/sql/backup.sql \
 && printf '<h1>Apache Server Status for matrix</h1>\n' > /srv/matrix/sens/status/server-status \
 && printf '<html><head><title>phpinfo()</title></head></html>\n' > /srv/matrix/sens/phpinfo/phpinfo.php \
 && printf '<html><body><form method="post"><input name="user"><input type="password" name="pw"></form></body></html>\n' \
      > /srv/matrix/login/admin/index.html \
 && printf '<html><body><form action="/search"><input type="text" name="q"></form></body></html>\n' \
      > /srv/matrix/search/login

COPY default.conf /etc/nginx/conf.d/default.conf
