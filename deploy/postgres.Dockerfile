FROM postgres:17-bookworm@sha256:5530681ea5d3e2ed4ce396f9b5cb443efbac6baf2a8a19c0c0635e40ae7eadce

RUN apt-get update \
    && apt-get install --yes --no-install-recommends postgresql-17-pgaudit=17.1-2.pgdg12+1 \
    && rm -rf /var/lib/apt/lists/*

COPY deploy/postgres/postgresql.conf /etc/postgresql/postgresql.conf
COPY deploy/postgres/pg_hba.conf /etc/postgresql/pg_hba.conf
COPY migrations/*.up.sql /docker-entrypoint-initdb.d/
COPY deploy/postgres/init/000001z_role_passwords.sh /docker-entrypoint-initdb.d/

RUN chmod 0444 /etc/postgresql/postgresql.conf /etc/postgresql/pg_hba.conf \
    && chmod 0444 /docker-entrypoint-initdb.d/*.up.sql \
    && chmod 0555 /docker-entrypoint-initdb.d/000001z_role_passwords.sh

CMD ["postgres", "-c", "config_file=/etc/postgresql/postgresql.conf"]
