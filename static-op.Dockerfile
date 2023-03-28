FROM golang:latest as build

COPY go.mod go.sum /build/
WORKDIR /build
RUN go mod download -x

COPY . /build/
RUN go build ./example/server

FROM busybox:glibc
COPY  --from=build /build/server /usr/local/bin/server

ENV ISSUER=http://localhost:9998/
EXPOSE 9998
CMD [ "/usr/local/bin/server" ]
