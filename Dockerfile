# Build stage: runs the test vectors, then builds a static binary.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go english.txt ./
COPY testdata ./testdata
RUN CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /znn-vanity .

# Runtime stage: just the binary, no shell, no network needed.
FROM scratch
COPY --from=build /znn-vanity /znn-vanity
WORKDIR /data
ENTRYPOINT ["/znn-vanity"]
