## sberf
Profiling/tracing/visualizing tool based on eBPF

Usage

```bash
sberf record
sberf stat
sberf top
sberf graph
```

TODO:
- design
- play with bcc
- implement
- enjoy

Building

```
# debug build
DEBUG=1 make

# build
make
```

location of installation

```
In
/usr/local

binary /usr/local/bin/sberf
 core and contribs in /usr/local/lib/sberf

Documentation:
 man /usr/local/share/man/man1/sberf.1
```

perf在browser.c中使用的是libslang绘制tui。

