# syntax=docker/dockerfile:1
ARG GO_VERSION=1.26.9
FROM golang:${GO_VERSION} AS build
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X github.com/Bugs5382/go-buildinfo.Version=${VERSION} -X github.com/Bugs5382/go-buildinfo.Commit=${COMMIT}" -o /out/identity ./cmd/identity
RUN CGO_ENABLED=0 go build -o /out/seed ./cmd/seed

# Demo-data image for dev and test environments only (`docker build --target
# seed`). The service image below never ships the seeder.
FROM gcr.io/distroless/static:nonroot AS seed
COPY --from=build /out/seed /seed
USER nonroot:nonroot
ENTRYPOINT ["/seed"]

# The service image (default target).
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/identity /identity
COPY --from=build /src/migrations /migrations
ENV MIGRATIONS_DIR=/migrations
USER nonroot:nonroot
ENTRYPOINT ["/identity"]
