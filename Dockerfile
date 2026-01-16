FROM mattermost/mattermost-enterprise-edition:release-11 AS original

FROM alpine:latest AS patcher
RUN apk add --no-cache bash xxd grep 

COPY --from=original /mattermost/bin/mattermost /mattermost

COPY patch.sh /tmp/patch.sh
RUN chmod +x /tmp/patch.sh && /tmp/patch.sh /mattermost

FROM mattermost/mattermost-enterprise-edition:release-11
COPY --from=patcher --chown=2000:2000 /mattermost /mattermost/bin/mattermost