#!/bin/bash
ssh XXX@pronto.las.iastate.edu 'squeue -h -u XXX --format "%j %N"' | cut -d ' ' -f2
