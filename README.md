# tofino-netcache

P4_16 implementation of [NetCache](https://dl.acm.org/doi/pdf/10.1145/3132747.3132764) targetted for the Intel Tofino ASIC. 

Adapted/ translated from:
- https://github.com/NUS-Systems-Lab/pegasus/tree/master/p4/netcache
- https://github.com/netx-repo/netcache-p4 (in progress)

Supported features:
- Key/ value cache
- Statistics engine

Unsupported features:
- No bitmap, i.e., memory optimizations

TODO:
- Control plane code

> Side notes: 
In the paper, the implementation is spread across the Ingress and Egress, however in this implementation we do everything in the Ingress only.

Code is not fully tested, yet. Thus, YMMV.