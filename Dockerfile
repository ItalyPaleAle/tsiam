FROM gcr.io/distroless/static-debian13:nonroot
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY .bin/linux-${TARGETARCH}/tsiam /bin
ENTRYPOINT [ "/bin/tsiam" ]
CMD ["/bin/tsiam"]
