package main

import (
    "encoding/binary"
    "fmt"
    "net"
    "os"

    "github.com/cilium/ebpf"
)

func key(s string) uint32 {
    ip := net.ParseIP(s).To4()
    if ip == nil {
        fmt.Println("invalid IPv4 address")
        os.Exit(1)
    }
    return binary.NativeEndian.Uint32(ip)
}

func main() {
    if len(os.Args) < 2 {
        fmt.Println("usage: fwctl add <ip> | del <ip> | list")
        return
    }
    m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/blocklist", nil)
    if err != nil { panic(err) }
    defer m.Close()

    switch os.Args[1] {
    case "add":
        if err := m.Put(key(os.Args[2]), uint8(1)); err != nil { panic(err) }
        fmt.Println("blocked", os.Args[2])
    case "del":
        if err := m.Delete(key(os.Args[2])); err != nil { panic(err) }
        fmt.Println("unblocked", os.Args[2])
    case "list":
        var k uint32
        var v uint8
        it := m.Iterate()
        for it.Next(&k, &v) {
            b := make([]byte, 4)
            binary.NativeEndian.PutUint32(b, k)
            fmt.Println(net.IP(b))
        }
    }
}