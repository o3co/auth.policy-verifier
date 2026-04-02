FROM node:22-alpine AS node-base

ENV HOME=/home/node

RUN apk add --no-cache tini \
 && npm install -g corepack --force \
 && corepack enable

WORKDIR /home/node

#############################################
FROM node-base AS deps

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages/core/package.json packages/core/package.json
COPY packages/foundation/package.json packages/foundation/package.json
COPY packages/express/package.json packages/express/package.json
COPY templates/standalone/package.json templates/standalone/package.json

RUN pnpm install --frozen-lockfile

#############################################
FROM deps AS builder

COPY tsconfig.base.json ./
COPY packages/core/ packages/core/
COPY packages/foundation/ packages/foundation/
COPY packages/express/ packages/express/
COPY templates/standalone/ templates/standalone/

RUN pnpm -r run build

#############################################
FROM node-base AS runtime

ENV NODE_ENV=production

COPY --from=deps /home/node/package.json /home/node/pnpm-workspace.yaml /home/node/pnpm-lock.yaml ./
COPY --from=deps /home/node/packages/core/package.json packages/core/package.json
COPY --from=deps /home/node/packages/foundation/package.json packages/foundation/package.json
COPY --from=deps /home/node/packages/express/package.json packages/express/package.json
COPY --from=deps /home/node/templates/standalone/package.json templates/standalone/package.json

RUN pnpm install --frozen-lockfile --prod \
 && pnpm store prune

COPY --from=builder /home/node/packages/core/dist/ packages/core/dist/
COPY --from=builder /home/node/packages/foundation/dist/ packages/foundation/dist/
COPY --from=builder /home/node/packages/express/dist/ packages/express/dist/
COPY --from=builder /home/node/templates/standalone/dist/ templates/standalone/dist/
COPY --from=builder /home/node/templates/standalone/config/ templates/standalone/config/

USER node

ENTRYPOINT ["tini", "--"]
CMD ["node", "templates/standalone/dist/main.mjs"]

#############################################
FROM builder AS test

RUN pnpm -r run test

#############################################
FROM builder AS develop

USER node

CMD ["pnpm", "--filter", "@o3co/auth-policy-verifier-standalone", "run", "debug"]
