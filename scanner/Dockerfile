
FROM golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b AS builder

ENV GOFLAGS=-trimpath GOTOOLCHAIN=local

RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

RUN CGO_ENABLED=0 go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.14.0 \
 && CGO_ENABLED=0 go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.3
RUN CGO_ENABLED=0 go install -v github.com/owasp-amass/amass/v5/...@v5.1.1
RUN CGO_ENABLED=0 go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0 \
 && CGO_ENABLED=0 go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.10.0
RUN CGO_ENABLED=1 go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libpcap0.8 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1000 scanner

COPY --from=builder /go/bin/ /usr/local/bin/

USER scanner
WORKDIR /home/scanner
ENTRYPOINT ["/bin/sh", "-c"]
