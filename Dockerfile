FROM golang:1.23-bookworm AS builder

WORKDIR /app

COPY go.mod go.sum ./
COPY vendor/ vendor/
RUN go mod verify
COPY pkg/ pkg/
COPY cmd/signing-server/ ./cmd/signing-server

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o signing-server cmd/signing-server/main.go

FROM alpine:3.16.0

WORKDIR /app

# Create appuser
ENV USER=appuser
ENV UID=10001
# See https://stackoverflow.com/a/55757473/12429735RUN
# and https://medium.com/@chemidy/create-the-smallest-and-secured-golang-docker-image-based-on-scratch-4752223b7324
RUN adduser \
--disabled-password \
--gecos "" \
--home "/nonexistent" \
--shell "/sbin/nologin" \
--no-create-home \
--uid "${UID}" \
"$USER"

COPY --from=builder app/signing-server /

# Use an unprivileged user.
USER ${USER}:${USER}

CMD ["/signing-server"]
