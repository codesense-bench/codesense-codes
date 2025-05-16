#!/bin/bash

function listXmls() {
    find traces_all/ -type f -name log.xml
}

listXmls | xmllint --format | 
