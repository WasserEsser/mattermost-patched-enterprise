ARG MATTERMOST_IMAGE_TAG=release-11
FROM mattermost/mattermost-enterprise-edition:${MATTERMOST_IMAGE_TAG} AS original

FROM alpine:latest AS patcher
RUN apk add --no-cache bash xxd grep gawk util-linux file

COPY --from=original /mattermost/bin/mattermost /mattermost

COPY patch.sh /tmp/patch.sh
RUN chmod +x /tmp/patch.sh && /tmp/patch.sh --quiet /mattermost

FROM mattermost/mattermost-enterprise-edition:${MATTERMOST_IMAGE_TAG}
COPY --from=patcher --chown=2000:2000 /mattermost /mattermost/bin/mattermost