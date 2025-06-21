1) Presumably the application is networked. It's possible to collect all network events received by the server from this
application per user, and the time period between any two events (e.g.: track time between connect() and first send()).
Vastly different time periods will be caused by breakpoints, tracing, etc. You can also look for consistently reoccurring
anomalous termination points (e.g.: connection terminating halfway through a sequence that usually succeeds &
takes 0.01 secs).

2) Send network events to the server if a debugger's presence is detected. For example, periodically calling
`ptrace(PTRACE_TRACEME)` on Linux, or `IsDebuggerPresent()` on Windows.

  - Save events to send later sending immediately fails. If the reverser is careless and re-runs the application on
    the same machine "normally" at a later time, you'll still receive the events.
