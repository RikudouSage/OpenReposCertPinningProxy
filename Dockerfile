FROM golang:1.26 AS build
WORKDIR /build
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app .

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y ca-certificates tzdata && rm -rf /var/lib/apt/lists/* && apt-get clean
COPY --from=build /app /app
ENTRYPOINT ["/app"]
