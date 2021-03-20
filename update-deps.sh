#!/bin/bash

RUNDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

if [[ ! $(which virtualenv) ]]; then
    echo "Must have virtualenv installed (run 'pip install virtualenv')"
    exit 1
fi

for rd in $(find ${RUNDIR} -name 'requirements-dev.txt'); do
    echo ${rd}
    virtualenv venv_temp
    source venv_temp/bin/activate
    pip install -r ${rd}
    pip freeze > $(dirname ${rd})/requirements.txt
    deactivate
    rm -rf venv_temp

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
