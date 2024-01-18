## Sberf
Profiling/tracing/visualizing tool based on eBPF

#### 编译

1. 安装[bpftool](https://github.com/libbpf/bpftool)

2. 安装[libbpf](https://github.com/libbpf/libbpf)

3. 安装Clang

```bash
# ubuntu
sudo apt-get install clang

# centos
sudo yum install clang
```

4. 编译

```
# 打印调试信息
DEBUG=1 make

# 无信息
make
```

#### 文件组成

`src`中存放`bpf.c`文件，用于加载到eBPF虚拟机上运行。

`.c`常规c文件。

`.h`常规c文件的头文件。

`Makefile` gnu-make的配置文件。

#### Makefile编译逻辑

```bash
# *.bpf.c: eBPF c文件
# *.bpf.o: clang和bpftool生成的eBPF目标文件*.bpf.o(在build_bpf文件夹中)
# *.skel.h: 使用*.bpf.o, 通过bpftool生成的skeleton header, 如sberf.skel.h(在build_bpf文件夹中)
# *.c: 普通c文件，通过include skeleton header调用eBPF
# *.o: 通过cc, 将所有常规.o文件链接，生成sberf可执行文件
#
# bpf.c --> bpf.tmp.o --> bpf.o --> skel.h
#                                      \_ .c -> .o
#                                 	             \_ sberf
```

<!--Usage-->

<!--```bash-->
<!--sberf record-->
<!--sberf stat-->
<!--sberf top-->
<!--sberf graph-->
<!--```-->

<!--TODO:-->
<!--- design-->
<!--- play with bcc-->
<!--- implement-->
<!--- enjoy-->

<!--Building-->

<!--```-->
<!--# debug build-->
<!--DEBUG=1 make-->

<!--# build-->
<!--make-->
<!--```-->

<!--location of installation-->

<!--```-->
<!--In-->
<!--/usr/local-->

<!--binary /usr/local/bin/sberf-->
 <!--core and contribs in /usr/local/lib/sberf-->

<!--Documentation:-->
 <!--man /usr/local/share/man/man1/sberf.1-->
<!--```-->

<!--perf在browser.c中使用的是libslang绘制tui。-->

