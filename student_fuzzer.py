from typing import Any, Optional, Callable, List, Type, Set, Tuple, Dict, Sequence
from types import FrameType, TracebackType

from fuzzingbook import GreyboxFuzzer as gbf
from fuzzingbook import Coverage as cv
from fuzzingbook import MutationFuzzer as mf

import numpy as np
import pickle
import hashlib

from bug import entrypoint
from bug import get_initial_corpus

# from myCustomBug import entrypoint
# from myCustomBug import get_initial_corpus

## You can re-implement the coverage class to change how
## the fuzzer tracks new behavior in the SUT


baseLocation = Tuple[str, int]
Location = Tuple[baseLocation,baseLocation]

class MyCoverage(cv.Coverage):

    # implement n-gram branch coverage

    def __init__(self) -> None:
        """Constructor"""
        self._trace: Dict[Location] = {}
        self.pathQueue = []
        self.nGramSize = 200

    # Trace function
    def traceit(self, frame: FrameType, event: str, arg: Any) -> Optional[Callable]:
        """Tracing function. To be overloaded in subclasses."""
        if self.original_trace_function is not None:
            self.original_trace_function(frame, event, arg)

        if event == "line":

            # Get func name and line number
            function_name = frame.f_code.co_name
            lineno = frame.f_lineno

            # Check if queue is below n gram size
            # add in current lines and function name
            if len(self.pathQueue) < self.nGramSize:
                self.pathQueue.append((function_name, lineno))
            else:
                self.pathQueue.pop(0)
                self.pathQueue.append((function_name, lineno))

            if function_name != '__exit__':  # avoid tracing ourselves:
                pickled = pickle.dumps(tuple(self.pathQueue))
                hashedRes = hashlib.md5(pickled).hexdigest()
                if hashedRes in self._trace:
                    self._trace[hashedRes] += 1
                else:
                    self._trace[hashedRes] = 1

        return self.traceit

    def coverage(self) -> Set[Location]:
        """The set of executed lines, as (function_name, line_number) pairs"""
        return set(self.trace())
    
    def trace(self):
        """The list of executed lines, as (function_name, line_number) pairs"""
        return self._trace
    

class MyRunner(mf.FunctionRunner):
    def run_function(self, inp: str) -> Any:
        with MyCoverage() as cov:
            try:
                result = super().run_function(inp)
            except Exception as exc:
                self._coverage = cov.coverage()
                raise exc

        self._coverage = cov.coverage()
        return result

    def coverage(self) -> Set[Location]:
        return self._coverage

    
# When executed, this program should run your fuzzer for a very 
# large number of iterations. The benchmarking framework will cut 
# off the run after a maximum amount of time
#
# The `get_initial_corpus` and `entrypoint` functions will be provided
# by the benchmarking framework in a file called `bug.py` for each 
# benchmarking run. The framework will track whether or not the bug was
# found by your fuzzer -- no need to keep track of crashing inputs

if __name__ == "__main__":
    
    seed_inputs_new = get_initial_corpus()
    fast_schedule_new = gbf.AFLFastSchedule(5)
    line_runner_new = MyRunner(entrypoint)

    fast_fuzzer_new = gbf.CountingGreyboxFuzzer(seed_inputs_new, gbf.Mutator(), fast_schedule_new)
    fast_fuzzer_new.runs(line_runner_new, trials=99999999)