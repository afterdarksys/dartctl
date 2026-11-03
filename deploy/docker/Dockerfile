# Build: docker build -f deploy/docker/Dockerfile -t dartctl .
# Run:   docker run -d --name dartctl --restart unless-stopped \
#          -v /etc/dartctl:/etc/dartctl:ro -v dartctl-state:/var/lib/dartctl \
#          -p 127.0.0.1:8787:8787 dartctl
# Set "listen": "0.0.0.0:8787" in monitor.json inside a container, and keep
# the published port on loopback behind your HTTPS proxy. The image runs as
# uid 65532: the mounted secret files must be mode 600 and owned by 65532 (or
# run with --user matching their owner), or dartctl refuses to read them.
# For reproducible builds, pin both base images by digest (@sha256:...).
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dartctl ./cmd/dartctl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /dartctl /usr/local/bin/dartctl
USER nonroot:nonroot
VOLUME ["/var/lib/dartctl"]
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/dartctl"]
CMD ["monitor", "serve", "--config", "/etc/dartctl/monitor.json"]
