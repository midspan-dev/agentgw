# syntax=docker/dockerfile:1
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/agentgw ./cmd/agentgw
# distroless has no shell or mkdir; make the state dir here, owned by nonroot (65532).
RUN mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/agentgw /agentgw
COPY --from=build --chown=65532:65532 /out/data /data
WORKDIR /data
USER 65532:65532
VOLUME /data
ENTRYPOINT ["/agentgw"]
