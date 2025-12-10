# Build image
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl xz-utils cmake make clang libc++-dev libc++abi-dev libomp-dev git ca-certificates \
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

RUN apt-get update && apt-get install -y --no-install-recommends libc++1 libc++abi1 libomp5 \
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
