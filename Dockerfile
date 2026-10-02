# syntax=docker/dockerfile:1
ARG GO_VERSION=1.26.6
FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/identity ./cmd/identity
RUN CGO_ENABLED=0 go build -o /out/seed ./cmd/seed
RUN CGO_ENABLED=0 go build -o /out/cutover ./cmd/cutover

# Demo-data image for dev and test environments only (`docker build --target
# seed`). The service image below never ships the seeder.
FROM gcr.io/distroless/static:nonroot AS seed
COPY --from=build /out/seed /seed
USER nonroot:nonroot
ENTRYPOINT ["/seed"]

# The service image (default target): the server plus the one-shot Kratos
# cutover tool.
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/identity /identity
COPY --from=build /out/cutover /cutover
COPY --from=build /src/migrations /migrations
ENV MIGRATIONS_DIR=/migrations
USER nonroot:nonroot
ENTRYPOINT ["/identity"]
