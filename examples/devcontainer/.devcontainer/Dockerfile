# SPDX-License-Identifier: Apache-2.0
# Agent image: non-root user, only what an agent session needs. Pinned by digest (SC-03).
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git python3 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 1000 --shell /bin/bash agent

# Install the agent client here, pinned to a version you reviewed, for example:
#   RUN npm install -g @anthropic-ai/claude-code@<version>   (needs nodejs in the image)

USER agent
WORKDIR /workspace
