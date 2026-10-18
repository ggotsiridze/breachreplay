# BreachReplay web UI: static build served by an unprivileged nginx that proxies the API.
ARG NODE_IMAGE=node:22-alpine
ARG NGINX_IMAGE=nginx:1.27-alpine

FROM ${NODE_IMAGE} AS build
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; fi; \
    npm ci --no-audit --no-fund
COPY frontend/ ./
COPY showcase /src/showcase
RUN npm run build

FROM ${NGINX_IMAGE}
COPY frontend/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /src/frontend/dist /usr/share/nginx/html
RUN chown -R 101:101 /var/cache/nginx
USER 101:101
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=4s --start-period=5s --retries=5 CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
