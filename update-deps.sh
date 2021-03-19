#!/bin/bash

RUNDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

if [[ ! $(which virtualenv) ]]; then
    echo "Must have virtualenv installed (run 'pip install virtualenv')"
    exit 1
fi

for rd in $(find ${RUNDIR} -name 'requirements-dev.txt'); do
    echo ${rd}
    echo virtualenv venv_temp
    echo source venv_temp/bin/activate
    echo pip install -r ${rd}
    echo deactivate
    echo rm -rf venv_temp
    echo '*****'

#    if [[ ! -d ${f} ]]; then
#        continue
#    fi
#
#    if [[ ! -d ${f}/tests ]]; then
#        continue
#    fi
#
#    echo ${f}/tests

done
