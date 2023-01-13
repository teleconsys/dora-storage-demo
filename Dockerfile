FROM rust:alpine3.17 AS build

# Set the current Working Directory inside the container
RUN mkdir /scratch
WORKDIR /scratch

# Copy everything from the current directory to the PWD(Present Working Directory) inside the container
COPY . .

RUN cargo build --release

############################
# Image
############################
# https://console.cloud.google.com/gcr/images/distroless/global/cc-debian11
# using distroless cc "nonroot" image, which includes everything in the base image (glibc, libssl and openssl)
FROM gcr.io/distroless/cc-debian11:nonroot

EXPOSE 9091/tcp

# Copy the app dir into distroless image
COPY --chown=nonroot:nonroot --from=build /target/release /app

WORKDIR /app
USER nonroot

ENTRYPOINT ["/app/dora-storage"]