# Build: docker build -f deploy/docker/Dockerfile -t dnctl .
# Run:   docker run -d --name dnctl --restart unless-stopped \
#          -v /etc/dnctl:/etc/dnctl:ro -v dnctl-state:/var/lib/dnctl \
#          -p 127.0.0.1:8787:8787 dnctl
# Set "listen": "0.0.0.0:8787" in monitor.json inside a container, and keep
# the published port on loopback behind your HTTPS proxy.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dnctl ./cmd/dnctl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /dnctl /usr/local/bin/dnctl
USER nonroot:nonroot
VOLUME ["/var/lib/dnctl"]
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/dnctl"]
CMD ["monitor", "serve", "--config", "/etc/dnctl/monitor.json"]
