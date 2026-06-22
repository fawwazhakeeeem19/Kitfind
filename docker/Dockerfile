



FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o kitfind ./cmd/kitfind/


FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata python3 py3-pip \
    && pip3 install --no-cache-dir dnspython requests beautifulsoup4 cryptography \
    && rm -rf /var/cache/apk/*

RUN addgroup -S kitfind && adduser -S -G kitfind kitfind
WORKDIR /app
COPY --from=builder /build/kitfind .
COPY --from=builder /build/configs ./configs
COPY --from=builder /build/modules ./modules
RUN chown -R kitfind:kitfind /app
USER kitfind

ENTRYPOINT ["/app/kitfind"]
CMD ["--help"]

LABEL org.opencontainers.image.title="KitFind"
LABEL org.opencontainers.image.description="Security Reconnaissance Tool — Authorized Use Only"
