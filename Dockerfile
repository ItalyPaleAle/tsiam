FROM gcr.io/distroless/static-debian12:nonroot
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY .bin/linux-${TARGETARCH}/tsiam /bin
CMD ["/bin/tsiam"]
