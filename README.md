# Parser for strace files

NB: The recommended strace options include : -f -ttt -T -
  -ttt gives microsecond absolute timestamps,
  -T gives syscall durations.
  -f follow forks (and threads); includes pids for single-thread processes too.
Other options have various (poor) tradeoffs.

# CLI

## strace-stats

Post-process a regular strace file to get stats such as strace -c would produce.

```
$ strace-stats FILENAME
"filename"
 % time     seconds  usecs/call     calls    errors syscall
------ ------------ ----------- --------- --------- ----------------
 96.86 29670.010031    0.306047     96946           futex
  1.76   539.832878    4.284388       126           epoll_wait
  0.64   196.346132    0.009388     20914           close
  0.27    82.860597    0.000639    129668           write
  0.21    65.616397    0.003282     19994           fchmod
```

Known bugs: errors are not reported (the parser is not semantic enough at this point).

# API

Parsing layers(core feature):
* Raw parsing layer: bytes -> structs/enums + day rollover detection.
* start/stop combination: combine half open events for the same syscall into one
  closed event

Exporters:
* Event Trace format(planned)

Analysis layers(speculative):
* lifetime analysis: analyse lifetime usage of resources
* concurrency analysis: look for interactions between syscalls

Ideally, no configuration needed, just feed the engine strace content, iterate
over the desired layer and done. However, if the format proves too ambiguous,
then the raw parsing layer will be the place that configuration takes place.
While it is possible to guarantee an unambiguous format by constraining the
versions and strace options supported, the closer to Just Works the better for
users - so there is a trade off between ease of use and reliability; for now
this is biasing to ease of use.

# Contributing

## Parsing failures

At minimum: a bug report with an attached strace snippet demonstrating the
failure.

If you have time, a PR with a regression test and bug fix would be great.

## Other things

A bug report that describes what you want to achieve, or a PR implementing it -
with at least enough testing that other authors don't need to worry about
undoing your work by mistake in future.

## Implementation notes

The parser is an internal detail - it may be reimplemented/switched out/whatever
in future.

# FAQ

## Q: Dealing with time

Timestamps are optional, or may be relative. So ideally we have absolute microsecond
timestamps (-ttt), but we may have only same-day (-t/-tt) or relative timestamps (-r)
or no time at all. In the
latter case while we can partially order the syscalls we cannot establish a
timeline, but we can still determine (some) concurrent syscalls using the ordering
given by `<unfinished ...>` markers.
For -t/-tt each time the clock rolls over we add an artificial day to the
durations returned.


## Q: Why isn't this just enhancements to
     https://github.com/wookietreiber/strace-analyzer ?
  A: https://github.com/wookietreiber/strace-analyzer#features-that-will-not-be-implemented
     - That project has admirable focus on being a CLI; I want a library to use
     for various process-a-strace file problems I run into.

# License

Apache-2.0

# Authors

Robert Collins