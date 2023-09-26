#!/bin/bash

REMOTE_SERVER="el01.ccs.local"
REMOTE_USER="ituser"

ansible-playbook -u "${REMOTE_USER}" -k -i "${REMOTE_SERVER}," -e host="${REMOTE_SERVER}" deploy-scripts-to-client.yml