#!/bin/sh

# Command ran by k8s to run migrations through codecov-api
echo "Running Django migrations"
cd codecov-api/

prefix=""
if [ -f "/usr/local/bin/berglas" ]; then
  prefix="berglas exec --"
fi

$prefix python manage.py migrate
$prefix python manage.py pgpartition --yes --skip-delete