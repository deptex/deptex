# Intentionally vulnerable: pinned old .NET image.
FROM mcr.microsoft.com/dotnet/sdk:6.0.100

# IaC misconfig: CKV_DOCKER_8 — running as root.
USER root

WORKDIR /app

COPY . .

RUN dotnet build -c Release || true

ENV PORT=4011
EXPOSE 4011

# IaC misconfig: CKV_DOCKER_2 — no HEALTHCHECK.

CMD ["dotnet", "run", "--no-build", "--urls", "http://0.0.0.0:4011"]
