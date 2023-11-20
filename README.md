# Student-Fuzzer-with-N-Gram-coverage-metric

Repository with an adapted N-Gram Coverage metric being implemented on a baseline greybox fuzzer

## Setup
Install all dependencies needed by the Fuzzing Book baseline fuzzer with:

```
pip install -r requirements.txt
```

You may want to do this in a Python **virtual environment** to avoid global dependency conflicts.

## Usage

The fuzzer expects a file named `bug.py` to be *in the same directory as the fuzzer file* (`student-fuzzer.py`).
This `bug.py` file should have two functions: an `entrypoint` that is fuzzed by the fuzzer and `get_initial_corpus` function which returns a list of initial inputs for the fuzzer.
To execute the fuzzer on the bug in `bug.py`, just run:

```
python student_fuzzer.py
```
