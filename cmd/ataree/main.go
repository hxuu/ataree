package main

import (
    "github.com/hxuu/ataree/bpf"
)

func main() {
    println("runtimed starting...")
    println("loading eBPF objects...")

    var objs bpf.MinimaltraceObjects 
    if err := bpf.LoadMinimaltraceObjects(&objs, nil); err != nil {
        println("error loading eBPF objects: ", err)
    }
    defer objs.Close()

    println("eBPF objects loaded successfully")
}

