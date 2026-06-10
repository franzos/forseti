#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
  CREATE USER kratos WITH PASSWORD 'secret';
  CREATE DATABASE kratos OWNER kratos;
  CREATE USER hydra  WITH PASSWORD 'secret';
  CREATE DATABASE hydra  OWNER hydra;
  CREATE USER jackson WITH PASSWORD 'secret';
  CREATE DATABASE jackson OWNER jackson;
EOSQL
