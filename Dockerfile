# Build image
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl=7.88.1-10+deb12u8 \
    xz-utils=5.4.1-0.2 \
    cmake=3.25.1-1 \
    make=4.3-4.1 \
    clang=1:14.0-55.7~deb12u1 \
    libc++-dev=1:14.0-55.7~deb12u1 \
    libc++abi-dev=1:14.0-55.7~deb12u1 \
    libomp-dev=1:14.0-55.7~deb12u1 \
    git=1:2.39.5-0+deb12u1 \
    ca-certificates=20230311 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz -o zig.tar.xz && \
    mkdir -p /usr/local/zig && \
    tar -xf zig.tar.xz -C /usr/local/zig --strip-components=1 && \
    ln -s /usr/local/zig/zig /usr/local/bin/zig && \
    rm zig.tar.xz

WORKDIR /app

# Build OpenFHE
COPY build.zig.zon /app/
COPY build.zig /app/
COPY third-party/ /app/third-party/
RUN rm -rf /app/third-party/openfhe/build && zig build openfhe

# Build the app
COPY src/ /app/src/
COPY lib/ /app/lib/
RUN zig build

# Final image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libc++1=1:14.0-55.7~deb12u1 \
    libc++abi1=1:14.0-55.7~deb12u1 \
    libomp5=1:14.0-55.7~deb12u1 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 1000 -m appuser

WORKDIR /app

COPY --from=build /app/zig-out/bin/GenZ /app/
COPY --from=build /app/zig-out/lib/*.so /app/lib/
COPY --from=build /app/third-party/openfhe/build/lib/*.so* /app/lib/

RUN chown -R appuser:appuser /app

USER appuser

ENV LD_LIBRARY_PATH=/app/lib

EXPOSE 5882

CMD [ "/app/GenZ" ]
