# Codebase Overview

This repository contains three main components related to execution tracing, benchmark dataset creation, and LLM evaluation.

## Benchmark Collection
- Purpose: Contains scripts to process and clean raw execution traces.
- Description: Converts raw traces into task-specific datasets suitable for various code understanding and reasoning benchmarks.

## Tracing Framework
- Purpose: Tools for collecting execution traces.
- Description: Supports tracing of Python, C, and Java programs to capture their runtime behavior and execution steps.

## LLM Evaluation
- Purpose: Scripts for evaluating Large Language Models (LLMs) on the task-specific datasets.
- Description: Runs evaluations, computes metrics, and benchmarks model performance on the curated datasets.

## Directory Structure
├── Benchmark Collection/ # Trace cleaning & dataset creation scripts
├── Tracing Framework/ # Trace collection tools for Python, C, Java
└── LLM Evaluation/ # LLM evaluation scripts on task-specific datasets