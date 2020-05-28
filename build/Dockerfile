FROM golang:1.14 as builder
WORKDIR /harbor-scanner-sysdig-secure
COPY go.mod go.sum ./
COPY . .
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s" -o harbor-scanner-sysdig-secure cmd/harbor-scanner-sysdig-secure/main.go
RUN strip harbor-scanner-sysdig-secure

FROM gcr.io/distroless/base
COPY --from=builder /harbor-scanner-sysdig-secure/harbor-scanner-sysdig-secure /bin/harbor-scanner-sysdig-secure
EXPOSE 5000
CMD ["/bin/harbor-scanner-sysdig-secure"]
