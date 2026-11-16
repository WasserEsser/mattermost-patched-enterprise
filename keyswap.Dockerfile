ARG MATTERMOST_IMAGE_TAG=12.1.0
FROM mattermost/mattermost-enterprise-edition:${MATTERMOST_IMAGE_TAG} AS original

FROM alpine:latest AS patcher
RUN apk add --no-cache bash xxd grep gawk util-linux file openssl

COPY --from=original /mattermost/bin/mattermost /mattermost

COPY patch.sh /tmp/patch.sh
COPY keyswap-key.pem /tmp/keyswap-key.pem

RUN chmod +x /tmp/patch.sh && /tmp/patch.sh --keyswap --quiet /mattermost

FROM mattermost/mattermost-enterprise-edition:${MATTERMOST_IMAGE_TAG}
COPY --from=patcher --chown=2000:2000 /mattermost /mattermost/bin/mattermost