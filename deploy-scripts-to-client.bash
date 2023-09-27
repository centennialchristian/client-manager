#!/bin/bash

source .testclient

ansible-playbook -u "${REMOTE_USER}" -k -i "${REMOTE_SERVER}," -e host="${REMOTE_SERVER}" deploy-scripts-to-client.yml