# ========================================================
# Stage: Builder
# ========================================================
# The Go version matches go.mod. The Xray core is built from ./core, the
# dialect fork in this repository: a stock core would silently drop dialects
# and the fork's other features.
FROM golang:1.27.1-alpine AS builder
WORKDIR /app

RUN apk --no-cache --update add \
  build-base \
  gcc \
  curl

COPY . .

ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-D_LARGEFILE64_SOURCE"
RUN go build -trimpath -ldflags "-w -s" -o build/x-ui main.go
RUN mkdir -p build/bin \
  && cd core \
  && CGO_ENABLED=0 go build -trimpath -ldflags "-w -s" -o "../build/bin/xray-linux-$(go env GOARCH)" ./main
RUN ./DockerInit.sh

# ========================================================
# Stage: Final Image of x-ui
# ========================================================
FROM alpine:3.22
ENV TZ=Asia/Tehran
WORKDIR /app

RUN apk add --no-cache --update \
  ca-certificates \
  tzdata \
  fail2ban \
  bash \
  curl \
  openssl

COPY --from=builder /app/build/ /app/
COPY --from=builder /app/DockerEntrypoint.sh /app/
COPY --from=builder /app/x-ui.sh /usr/bin/x-ui


# Configure fail2ban
RUN rm -f /etc/fail2ban/jail.d/alpine-ssh.conf \
  && cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local \
  && sed -i "s/^\[ssh\]$/&\nenabled = false/" /etc/fail2ban/jail.local \
  && sed -i "s/^\[sshd\]$/&\nenabled = false/" /etc/fail2ban/jail.local \
  && sed -i "s/#allowipv6 = auto/allowipv6 = auto/g" /etc/fail2ban/fail2ban.conf

RUN chmod +x \
  /app/DockerEntrypoint.sh \
  /app/x-ui \
  /usr/bin/x-ui

ENV XUI_ENABLE_FAIL2BAN="true"
EXPOSE 60000
VOLUME [ "/etc/x-ui" ]
CMD [ "./x-ui" ]
ENTRYPOINT [ "/app/DockerEntrypoint.sh" ]
