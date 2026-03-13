package main

import (
    "github.com/hxuu/ataree/internal/ebpf"
)

func main() {
    println("runtimed starting...")
    println("loading eBPF objects...")

    var objs ebpf.MinimaltraceObjects 
    if err := ebpf.LoadMinimaltraceObjects(&objs, nil); err != nil {
        println("error loading eBPF objects: ", err)
    }
    defer objs.Close()

    println("eBPF objects loaded successfully")
}

