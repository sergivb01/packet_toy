# Pkcap

Testing gopacket for my personal website's backend

```
mar 10 may 2022 01:13:41 CEST
goos: linux
goarch: amd64
pkg: pkcap
cpu: AMD Ryzen 7 5800H with Radeon Graphics
BenchmarkDecodePackets-16         360121              3036 ns/op
BenchmarkDecodePackets2-16       1000000              1077 ns/op
BenchmarkDecodePackets3-16        349202              3482 ns/op
PASS
ok      pkcap   47.693s
```
> DecodePackets2 can decode 928,505 PPS


```
mar 10 may 2022 09:36:23 CEST
goos: linux
goarch: amd64
pkg: pkcap
cpu: Intel(R) Core(TM) i5-9600 CPU @ 3.10GHz
BenchmarkDecodePackets-6          666488              1681 ns/op
BenchmarkDecodePackets2-6        3085256               386.6 ns/op
BenchmarkDecodePackets3-6         524146              2115 ns/op
PASS
ok      pkcap   74.244s
```
> DecodePackets2 can decode 25,906,735 PPS

### Links:

- https://groups.google.com/g/golang-nuts/c/MOUEqi-b1S0?pli=1
- https://pkg.go.dev/runtime#LockOSThread
- https://pkg.go.dev/github.com/google/gopacket?utm_source=godoc#hdr-Pointers_To_Known_Layers
- https://pkg.go.dev/github.com/google/gopacket#hdr-NoCopy_Decoding
- https://pkg.go.dev/github.com/google/gopacket#hdr-Fast_Decoding_With_DecodingLayerParser
