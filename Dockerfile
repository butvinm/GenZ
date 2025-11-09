FROM alpine:3.22.2 AS build

RUN apk add --no-cache curl tar xz

RUN curl -L https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz -o zig.tar.xz && \
    mkdir -p /usr/local/zig && \
    tar -xf zig.tar.xz -C /usr/local/zig --strip-components=1 && \
    ln -s /usr/local/zig/zig /usr/local/bin/zig && \
    rm zig.tar.xz

WORKDIR /app

COPY build.zig.zon /app/
COPY build.zig /app/
COPY src/ /app/src

RUN zig build

FROM alpine:3.22.2

WORKDIR /app

COPY --from=build /app/zig-out/bin/GenZ /app

EXPOSE 5882

CMD [ "/app/GenZ" ]
