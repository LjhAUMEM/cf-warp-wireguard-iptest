#Use
```
-4 | test with build in ipv4 | default false
-6 | test with build in ipv6 | default false
-n | number of concurrencies | default 200
-p | port to test | default 500
-f | specifying the cidr file | default none
-t | times of single endpoint peer tests | default 3
-o | output file | defult result.txt
-mtu | mtu | default 1280
```

#Example
```
./warp -6 -result.6.txt
```

#Build
check build.md

#Thanks to:
[peanut996/CloudflareWarpSpeedTest](https://github.com/peanut996/CloudflareWarpSpeedTest)
[ViRb3/wgcf](https://github.com/ViRb3/wgcf)
[WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)