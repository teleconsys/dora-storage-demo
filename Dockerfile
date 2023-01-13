FROM rust:latest AS build

# Ensure ca-certificates are up to date
RUN update-ca-certificates

# Set the current Working Directory inside the container
RUN mkdir /scratch
WORKDIR /scratch
RUN mkdir /dora-storage
RUN mkdir /kyber-rs

# Copy everything from the current directory to the PWD(Present Working Directory) inside the container
COPY dora-storage/. dora-storage/.
COPY kyber-rs/. kyber-rs/.
WORKDIR /scratch/dora-storage

RUN cargo build --release

WORKDIR /scratch
RUN mkdir /app
RUN mv dora-storage/target/release/dora-storage /app

############################
# Image
############################
# https://console.cloud.google.com/gcr/images/distroless/global/cc-debian11
# using distroless cc "nonroot" image, which includes everything in the base image (glibc, libssl and openssl)
FROM gcr.io/distroless/cc-debian11:nonroot

EXPOSE 9000/tcp
EXPOSE 8000/tcp

# Copy the app dir into distroless image
COPY --chown=nonroot:nonroot --from=build /app /app

WORKDIR /app
USER nonroot

ENTRYPOINT ["/app/dora-storage"]