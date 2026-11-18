# Create writable state directories for user 65532
# This stage only creates directories, so it runs on the build platform without emulation
FROM --platform=$BUILDPLATFORM gcr.io/distroless/static-debian13:debug-nonroot@sha256:7df9fac2f5d3927260696af33fc2391da26366825838a47337088ed78f854a0c AS dirs
RUN ["/busybox/mkdir", "-p", "-m", "0700", "/tmp/rootfs/etc/tsiam/tsnet", "/tmp/rootfs/var/lib/tsiam"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY --from=dirs --chown=65532:65532 /tmp/rootfs/etc/ /etc/
COPY --from=dirs --chown=65532:65532 /tmp/rootfs/var/lib/ /var/lib/
COPY --chmod=0555 .bin/linux-${TARGETARCH}/tsiam /bin/tsiam
ENTRYPOINT ["/bin/tsiam"]
