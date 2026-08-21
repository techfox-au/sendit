# syntax=docker/dockerfile:1
#
# Sendit — API only (no frontend, no nginx).
# Host nginx serves public/ and proxies /api/ → this container.
#
#   python3 scripts/build-frontend.py
#   rsync public/ → /var/www/sendit/public
#   docker compose -f deploy/docker-compose.yml up -d --build
#
# See deploy/nginx/sendit.conf

# ---- .NET build (cross-compile to TARGETARCH musl RID) ----
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
WORKDIR /src

RUN case "$TARGETARCH" in \
      amd64) echo linux-musl-x64  > /tmp/rid ;; \
      arm64) echo linux-musl-arm64 > /tmp/rid ;; \
      *)     echo "Unsupported TARGETARCH=$TARGETARCH (need amd64 or arm64)" >&2; exit 1 ;; \
    esac \
 && echo "Publishing self-contained for RID=$(cat /tmp/rid)"

COPY Sendit.slnx ./
COPY src/Sendit.Api/Sendit.Api.csproj src/Sendit.Api/
RUN RID=$(cat /tmp/rid) \
 && dotnet restore src/Sendit.Api/Sendit.Api.csproj -r "$RID"

# Source only (repo .dockerignore excludes host bin/obj so restore is not clobbered)
COPY src/Sendit.Api/ src/Sendit.Api/
RUN RID=$(cat /tmp/rid) \
 && rm -rf src/Sendit.Api/obj src/Sendit.Api/bin \
 && dotnet restore src/Sendit.Api/Sendit.Api.csproj -r "$RID" \
 && dotnet publish src/Sendit.Api/Sendit.Api.csproj \
      -c Release \
      -r "$RID" \
      --self-contained true \
      -o /app/publish \
      --no-restore \
      /p:UseAppHost=true \
      /p:PublishTrimmed=false

# ---- Runtime ----
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-alpine AS final
WORKDIR /app

# fontconfig + DejaVu: libSkiaSharp needs fontconfig; DejaVu is used to rasterize
# themed email CTA button labels (Outlook dark mode cannot recolour PNG pixels).
RUN apk add --no-cache fontconfig ttf-dejavu \
    && addgroup -g 10001 -S sendit \
    && adduser -u 10001 -S -G sendit -h /app -s /sbin/nologin sendit \
    && mkdir -p /data \
    && chown -R sendit:sendit /data /app

COPY --from=build --chown=sendit:sendit /app/publish .
# Branding (logo.svg, favicon, logo.png) is generated in-process from SENDIT_HIGHLIGHT.
RUN chmod +x /app/Sendit.Api

ENV ASPNETCORE_URLS=http://0.0.0.0:8080 \
    SENDIT_DB_PATH=/data/sendit.db \
    SENDIT_EDGE_SECURITY_HEADERS=1 \
    DOTNET_EnableDiagnostics=0 \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=true

USER sendit
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["./Sendit.Api"]
