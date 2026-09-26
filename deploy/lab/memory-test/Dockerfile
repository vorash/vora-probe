# Lab workload image. Built locally and imported into the k3s containerd rather
# than pushed to a registry: the Vora test host has no build tooling and a lab
# image does not need a public tag.

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/memory-test .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/memory-test /usr/local/bin/memory-test
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/memory-test"]
