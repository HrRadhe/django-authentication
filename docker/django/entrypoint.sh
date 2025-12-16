#!/bin/bash

set -e

MANAGE_PY="./manage.py"

echo "Checking if database is ready..."

echo "Applying Database Migrations..."
python $MANAGE_PY makemigrations
python $MANAGE_PY migrate

echo "Collecting Static Files..."
python $MANAGE_PY collectstatic --noinput

echo "Starting Server..."


exec "$@"