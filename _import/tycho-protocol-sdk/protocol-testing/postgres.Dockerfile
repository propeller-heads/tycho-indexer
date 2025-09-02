# This Dockerfile creates a custom postgres image used for CI and local deployment.
# This is required because we use some postgres extensions that aren't in the generic 
# Postgres image such as pg_partman or pg_cron.

# As an image with pg_partman already exist, we start from this one and add pg_cron 
# and possibly other extensions on top of that.
FROM ghcr.io/dbsystel/postgresql-partman:15-5
ARG PGCRON_VERSION="1.6.2"
USER root
RUN cd /tmp \
    && wget "https://github.com/citusdata/pg_cron/archive/refs/tags/v${PGCRON_VERSION}.tar.gz" \
    && tar zxf v${PGCRON_VERSION}.tar.gz \
    && cd pg_cron-${PGCRON_VERSION} \
    && make \
    && make install \
    && cd .. && rm -r pg_cron-${PGCRON_VERSION} v${PGCRON_VERSION}.tar.gz
RUN echo "cron.database_name = 'tycho_indexer_0'" >> /opt/bitnami/postgresql/conf/postgresql.conf
USER 1001