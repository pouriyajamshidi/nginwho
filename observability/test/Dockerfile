# builds nginwho from this repo, then runs it on a small Debian
FROM nimlang/nim:2.2.12 AS build
WORKDIR /src
COPY nginwho.nimble config.nims ./
COPY src ./src
RUN nimble install -y --depsOnly && \
  nimble c -d:release --opt:speed -d:ssl --hints:off -o:/nginwho src/nginwho.nim

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libsqlite3-0 libssl3 ca-certificates && \
  rm -rf /var/lib/apt/lists/*
COPY --from=build /nginwho /usr/local/bin/nginwho
