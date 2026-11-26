# syntax=docker/dockerfile:1

ARG MATTERMOST_IMAGE_TAG=12.1.0
FROM mattermost/mattermost-enterprise-edition:${MATTERMOST_IMAGE_TAG} AS original

FROM alpine:latest AS patcher
RUN apk add --no-cache bash xxd grep gawk util-linux file openssl

COPY --from=original /mattermost/bin/mattermost /mattermost

COPY patch.sh /tmp/patch.sh
# Mount the private key as a BuildKit secret so it is available to patch.sh at
# build time but never baked into an image layer or the build cache. It is read
# from keyswap-key.pem in the build context via:
#   docker build --secret id=keyswap-key,src=./keyswap-key.pem -f keyswap.Dockerfile .
RUN --mount=type=secret,id=keyswap-key,target=/tmp/keyswap-key.pem \
    chmod +x /tmp/patch.sh && /tmp/patch.sh --keyswap --quiet /mattermost

ARG MATTERMOST_IMAGE_TAG
FROM mattermost/mattermost-enterprise-edition:${MATTERMOST_IMAGE_TAG}
COPY --from=patcher --chown=2000:2000 /mattermost /mattermost/bin/mattermost
