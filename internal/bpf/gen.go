package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type imds_event -target bpfel,bpfeb bpf ../../bpf/connect_hook.c -- -I../../bpf
