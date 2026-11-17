# buildclamp — a static musl binary on `scratch`.
#
# The image is the binary. No shell, no package manager, no libc, nothing to exec into.
# That is not minimalism for its own sake: this container is put in front of a build to
# constrain what that build may do, so every byte in it that is not the binary is attack
# surface with no compensating value.
#
#   docker build -t buildclamp .
#
# The usual way to use it is to take the binary into the image your build runs in:
#
#   COPY --from=mancube/buildclamp:0.2 /cargo-buildclamp /usr/local/cargo/bin/cargo-buildclamp
#
# NOTE ON RUNNING IT IN A CONTAINER, which is where most people will want it:
# buildclamp needs user namespaces and seccomp to enforce anything, and the default Docker
# seccomp profile denies `unshare`. Without them it reports `advisory` or refuses to run a
# unit rather than running it unheld — which is correct, and is not what anybody wants from
# their CI. Run it with:
#
#   docker run --security-opt seccomp=unconfined --security-opt apparmor=unconfined ...
#
# and check with `buildclamp doctor` before trusting a green build. `--require-enforced`
# turns a silently-degraded run into a failed one, and belongs in CI.
#
# The release workflow replaces the `bin` stage with the release's own static binaries
# (`--build-context bin=dist/`, holding amd64/cargo-buildclamp and arm64/cargo-buildclamp),
# so the image carries exactly the bytes attached to the GitHub release and nothing is
# compiled under emulation. Built from source, `bin` comes from `build` below.

FROM rust:1.94-alpine AS build
ARG TARGETARCH
RUN apk add --no-cache musl-dev file
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# --locked: the lockfile is the build. It matters more here than in most projects — this
# tool's entire subject is what a build resolves and then executes, and a container that
# resolved its own dependencies at build time would not be the artefact anyone tested.
RUN case "${TARGETARCH}" in \
      amd64) T=x86_64-unknown-linux-musl ;; \
      arm64) T=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}: buildclamp enforces on x86_64 and aarch64" >&2; exit 1 ;; \
    esac \
 && rustup target add "$T" \
 && cargo build --release --locked --target "$T" -p cargo-buildclamp \
 && strip "target/$T/release/cargo-buildclamp" \
 && mkdir -p "/out/${TARGETARCH}" \
 && cp "target/$T/release/cargo-buildclamp" "/out/${TARGETARCH}/cargo-buildclamp"

# Prove the static claim inside the builder, where a failure is a build failure rather than
# a runtime surprise on somebody else's machine.
# `file`, not `ldd`: musl's ldd reports a static-pie binary as dynamic.
RUN file "/out/${TARGETARCH}/cargo-buildclamp" | grep -Eq "statically linked|static-pie linked"

FROM scratch AS bin
COPY --from=build /out /

FROM scratch
ARG TARGETARCH
COPY --from=bin --chmod=0755 /${TARGETARCH}/cargo-buildclamp /cargo-buildclamp
COPY LICENSE NOTICE /

ENTRYPOINT ["/cargo-buildclamp"]
CMD ["buildclamp", "doctor"]
