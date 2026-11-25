# Create writable state directories for user 65532
# This stage only creates directories, so it runs on the build platform without emulation
FROM --platform=$BUILDPLATFORM gcr.io/distroless/static-debian13:debug-nonroot@sha256:3e7f48d714a3298b4df1a69fbc8809dd6fadd16c306838862fffc2895b168158 AS dirs
RUN ["/busybox/mkdir", "-p", "-m", "0700", "/tmp/rootfs/etc/tsiam/tsnet", "/tmp/rootfs/var/lib/tsiam"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY --from=dirs --chown=65532:65532 /tmp/rootfs/etc/ /etc/
COPY --from=dirs --chown=65532:65532 /tmp/rootfs/var/lib/ /var/lib/
COPY --chmod=0555 .bin/linux-${TARGETARCH}/tsiam /bin/tsiam
ENTRYPOINT ["/bin/tsiam"]
