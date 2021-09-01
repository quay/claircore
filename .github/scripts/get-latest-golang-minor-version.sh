#!/usr/bin/env bash
MAJOR_VERSION=$1
LOGFILE=$2

LATEST_MINOR_VERSION=0

LATEST_VERSION="none"
CHECK_VERSION=$MAJOR_VERSION

while true
do
    URL=https://dl.google.com/go/go${CHECK_VERSION}.linux-amd64.tar.gz
    echo -n "${URL} " >> ${LOGFILE}
    HTTP_RESP_CODE=`curl -I -o /dev/null -s -w "%{http_code}\n" "${URL}"`
    echo "${HTTP_RESP_CODE}" >> ${LOGFILE}
    if [[ HTTP_RESP_CODE -ne 200 ]]
    then
        break
    fi
    LATEST_VERSION=${CHECK_VERSION}
    let CHECK_MINOR_VERSION++
    CHECK_VERSION=${MAJOR_VERSION}.${CHECK_MINOR_VERSION}
done

# Return latest Golang version available for download in format "1.15.6"
echo "${LATEST_VERSION}"
