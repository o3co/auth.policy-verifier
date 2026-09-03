# The base image is pinned by digest, not just by tag: `node:24-alpine` is a
# moving pointer, so the same source produced a different image on every
# rebuild. The digest is the multi-arch index, so amd64 and arm64 both resolve
# from it. Dependabot's `docker` ecosystem keeps the pair in step — bump the
# tag and the digest together, never the tag alone.
FROM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS node-base

ENV HOME=/home/node

# corepack is pinned too. `npm install -g corepack --force` resolved whatever
# was latest at build time, which is a mutable dependency of every build. The
# pnpm version itself comes from the `packageManager` field in package.json,
# which corepack reads.
RUN apk add --no-cache tini \
 && npm install -g corepack@0.35.0 --force \
 && corepack enable

WORKDIR /home/node

#############################################
FROM node-base AS deps

# pnpm-lock.yaml is a required build input: `create-auth-policy-verifier`
# generates it at scaffold time and the project commits it. Without it this
# COPY fails, which is the intended outcome — a build that silently re-resolves
# every dependency range is the thing this file stopped doing.
COPY --chown=node:node package.json pnpm-lock.yaml ./

USER node

# --frozen-lockfile: install exactly what the lockfile pins, and fail if
# package.json and the lockfile disagree, rather than quietly rewriting it.
RUN pnpm install --frozen-lockfile

#############################################
FROM deps AS builder

# USER node inherited from deps stage; repeated here to make the builder
# hardening invariant obvious in Dockerfile reviews.
USER node

# tsconfig*.json, not tsconfig.json: the template also ships
# tsconfig.typecheck.json, which is what `pnpm run typecheck` reads. Copying the
# whole set keeps the test and develop stages able to run it.
COPY --chown=node:node tsconfig*.json ./
COPY --chown=node:node config/ ./config/
COPY --chown=node:node src/ ./src/

RUN pnpm run build

#############################################
# Dependencies are resolved once, in `deps`. This stage drops the dev half of
# that same tree instead of running a second `pnpm install --prod` in the
# runtime stage: a second install is a second resolution, and therefore a
# second chance for the runtime image to hold something the build never saw.
FROM deps AS prod-deps

USER node

RUN pnpm prune --prod

#############################################
FROM node-base AS runtime

ENV NODE_ENV=production

COPY --from=deps /home/node/package.json /home/node/pnpm-lock.yaml ./
COPY --from=prod-deps /home/node/node_modules/ ./node_modules/
COPY --from=builder /home/node/dist/ ./dist/
COPY --from=builder /home/node/config/ ./config/

USER node

ENV HTTP_PORT=3000
EXPOSE ${HTTP_PORT}

# Probes the container's own routable address, NOT 127.0.0.1 — deliberately.
#
# `application.conf` binds loopback by default (#108), because /verify answers
# with an authorization decision and a reachable port is a decision oracle. A
# container that keeps that default is reachable from nothing: the published
# port never connects. A probe against 127.0.0.1 passes anyway — inside the
# container loopback is exactly where the server is listening — so it would
# report "healthy" for a container no caller can reach. That is the one failure
# this check exists to catch, so it asks the same question a caller does:
# "does the port answer at the address the container is reachable at?"
#
# `hostname -i` yields the container's IP; a v6 literal is bracketed for the
# URL. `${HTTP_PATH_PREFIX}` keeps the probe on the mount point the server
# actually used (`http.pathPrefix`), and `${HTTP_PORT}` keeps it on the
# operator's port — the config reads `${?HTTP_PORT}`, so app.listen() and the
# probe stay in sync. Shell form, so both expand at probe time.
#
# `GET /_healthcheck` is the liveness path every component of the stack answers
# on (`/healthcheck` stays as a compatibility alias). It is never gated by
# `http.callerAuth`, so setting HTTP_CALLER_AUTH_TOKEN does not require a
# credential here.
#
# The deployment where loopback is genuinely correct — a sidecar sharing a
# network namespace with its caller — is the one shape this check is wrong for.
# That deployment overrides `healthcheck:` per service, which keeps the
# restart-driving signal honest for everyone else.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD addr="$(hostname -i | cut -d' ' -f1)"; \
      case "$addr" in *:*) addr="[$addr]" ;; esac; \
      wget -q -O /dev/null "http://${addr}:${HTTP_PORT}${HTTP_PATH_PREFIX%/}/_healthcheck" || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["node", "dist/main.mjs"]

#############################################
FROM builder AS test

CMD ["pnpm", "run", "test", "--", "--passWithNoTests"]

#############################################
FROM builder AS develop

USER node

CMD ["pnpm", "run", "debug"]
