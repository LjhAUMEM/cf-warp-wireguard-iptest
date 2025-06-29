package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"a/wgcf"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

var warpHandshakePacket, _ = hex.DecodeString("013cbdafb4135cac96a29484d7a0175ab152dd3e59be35049beadf758b8d48af14ca65f25a168934746fe8bc8867b1c17113d71c0fac5c141ef9f35783ffa5357c9871f4a006662b83ad71245a862495376a5fe3b4f2e1f06974d748416670e5f9b086297f652e6dfbf742fbfc63c3d8aeb175a3e9b7582fbc67c77577e4c0b32b05f92900000000000000000000000000000000")
var mtu = 1280

// "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
// func generateWireGuardKeyHexString() (string, string) {
// 	privateKey, _ := wgtypes.GeneratePrivateKey()
// 	publicKey := privateKey.PublicKey()
// 	return hex.EncodeToString(privateKey[:]), hex.EncodeToString(publicKey[:])
// }

// "golang.org/x/crypto/curve25519"
// func generateWireGuardKeyHexString() (string, string) {
// 	var privateKey, publicKey []byte
// 	privateKey = make([]byte, curve25519.ScalarSize)
// 	rand.Read(privateKey)
// 	privateKey[0] &= 248
// 	privateKey[31] &= 127
// 	privateKey[31] |= 64
// 	publicKey, _ = curve25519.X25519(privateKey, curve25519.Basepoint)
// 	return hex.EncodeToString(privateKey), hex.EncodeToString(publicKey)
// }

func GenHandshakePacket(privateKey, publicKey, clientId string) []byte {
	priBytes, _ := base64.StdEncoding.DecodeString(privateKey)
	pubBytes, _ := base64.StdEncoding.DecodeString(publicKey)
	clientIdBytes, _ := base64.StdEncoding.DecodeString(clientId)

	noi_pri := device.NoisePrivateKey{}
	noi_pri.FromHex(hex.EncodeToString(priBytes))
	noi_pub := device.NoisePublicKey{}
	noi_pub.FromHex(hex.EncodeToString(pubBytes))

	tun, _, err := netstack.CreateNetTUN([]netip.Addr{}, []netip.Addr{}, mtu)
	if err != nil {
		panic(err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	dev.SetPrivateKey(noi_pri)

	peer, err := dev.NewPeer(noi_pub)
	if err != nil {
		panic(err)
	}

	msg, err := dev.CreateMessageInitiation(peer)
	if err != nil {
		panic(err)
	}

	var buf [device.MessageInitiationSize]byte
	writer := bytes.NewBuffer(buf[:0])

	binary.Write(writer, binary.LittleEndian, msg)
	packet := writer.Bytes()

	generator := device.CookieGenerator{}
	generator.Init(noi_pub)
	generator.AddMacs(packet)

	packet[1], packet[2], packet[3] = clientIdBytes[0], clientIdBytes[1], clientIdBytes[2]

	return packet
}

func GenHandshakePacket2(privateKey, publicKey, clientId string) []byte {
	priBytes, _ := base64.StdEncoding.DecodeString(privateKey)
	pubBytes, _ := base64.StdEncoding.DecodeString(publicKey)
	clientIdBytes, _ := base64.StdEncoding.DecodeString(clientId)

	noi_pri := device.NoisePrivateKey{}
	noi_pri.FromHex(hex.EncodeToString(priBytes))
	noi_pub := device.NoisePublicKey{}
	noi_pub.FromHex(hex.EncodeToString(pubBytes))

	dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	dev.SetPrivateKey(noi_pri)

	peer, err := dev.NewPeer(noi_pub)
	if err != nil {
		panic(err)
	}

	msg, err := dev.CreateMessageInitiation(peer)
	if err != nil {
		panic(err)
	}

	var buf [device.MessageInitiationSize]byte
	writer := bytes.NewBuffer(buf[:0])

	binary.Write(writer, binary.LittleEndian, msg)
	packet := writer.Bytes()

	generator := device.CookieGenerator{}
	generator.Init(noi_pub)
	generator.AddMacs(packet)

	packet[1], packet[2], packet[3] = clientIdBytes[0], clientIdBytes[1], clientIdBytes[2]

	return packet
}

func init() {
	privateKey, publicKey, clientId := wgcf.Get()
	// fmt.Println("privateKey", privateKey)
	// fmt.Println("publicKey", publicKey)
	// fmt.Println("clientId", clientId)
	// clientIdBytes, _ := base64.StdEncoding.DecodeString(clientId)
	// fmt.Println("reserved len", len(clientId))
	// fmt.Println("reserved b64", clientId)
	// fmt.Println("reserved hex", hex.EncodeToString(clientIdBytes))
	// fmt.Println("reserved int", clientIdBytes)
	newPacket := GenHandshakePacket(privateKey, publicKey, clientId)
	// newPacket2 := GenHandshakePacket2(privateKey, publicKey, clientId)
	// fmt.Println(hex.EncodeToString(warpHandshakePacket))
	// fmt.Println(hex.EncodeToString(newPacket))
	// fmt.Println(hex.EncodeToString(newPacket2))
	warpHandshakePacket = newPacket
}

func Check(host string, port string) error {
	// fmt.Println(host, port)

	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, port), time.Millisecond*1000)
	if err != nil {
		// fmt.Printf("连接失败: %v\n", err)
		return err
	}
	defer conn.Close()

	_, err = conn.Write(warpHandshakePacket)
	if err != nil {
		// fmt.Printf("发送失败: %v\n", err)
		return err
	}

	err = conn.SetDeadline(time.Now().Add(time.Millisecond * 1000))
	if err != nil {
		// fmt.Printf("设置超时失败: %v\n", err)
		return err
	}

	revBuff := make([]byte, 1024)
	n, err := conn.Read(revBuff)
	if err != nil {
		// fmt.Printf("读取失败: %v\n", err)
		return err
	}

	if n != device.MessageResponseSize {
		fmt.Printf("(%s, %s) 响应长度错误: 期望%d字节, 实际%d字节\n", host, port, device.MessageResponseSize, n)
		return fmt.Errorf("")
	}

	return nil
}

var (
	v4   bool
	v6   bool
	port string
	file string
	n    int
	try  int
	out  string
)

func main() {
	// Check("162.159.192.1", "500")
	// Check("162.159.192.2", "854")
	// Check("162.159.192.3", "880")
	// Check("188.114.96.1", "500")
	// Check("188.114.96.2", "854")
	// Check("188.114.96.3", "880")

	flag.BoolVar(&v4, "4", false, "")
	flag.BoolVar(&v6, "6", false, "")
	flag.StringVar(&port, "p", "500", "")
	flag.StringVar(&file, "f", "", "")
	flag.IntVar(&n, "n", 200, "")
	flag.IntVar(&try, "t", 3, "")
	flag.StringVar(&out, "o", "result.txt", "")
	flag.IntVar(&mtu, "mtu", 1280, "")
	flag.Parse()

	cidrs := []string{}

	cidrs4 := []string{
		"162.159.192.0/24",
		"162.159.193.0/24",
		"162.159.195.0/24",
		"162.159.204.0/24",
		"188.114.96.0/24",
		"188.114.97.0/24",
		"188.114.98.0/24",
		"188.114.99.0/24",
	}

	cidrs6 := []string{
		"2606:4700:d0::/48",
		"2606:4700:d1::/48",
		"2606:4700:d0::/96",
		"2606:4700:d1::/96",
		"2606:4700:d0::a29f:c001/112",
		"2606:4700:d0::a29f:c001/112",
	}

	hosts := []string{}

	tasks := make(chan struct {
		host string
		port string
	})

	results := make(chan struct {
		host      string
		port      string
		delay     time.Duration
		successes int
	})

	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			panic(fmt.Sprintf("无法打开文件: %v", err))
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				cidrs = append(cidrs, line)
			}
		}
		if err := scanner.Err(); err != nil {
			panic(fmt.Sprintf("读取文件出错: %v", err))
		}
	}

	if v4 {
		cidrs = append(cidrs, cidrs4...)
	}

	if v6 {
		cidrs = append(cidrs, cidrs6...)
	}

	for _, cidr := range cidrs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			if prefix.Addr().Is6() {
				ips, _ := GenerateIPv6Addresses(cidr, 1024)
				for _, v := range ips {
					hosts = append(hosts, v.String())
				}
			} else {
				for ip := prefix.Masked().Addr(); prefix.Contains(ip); ip = ip.Next() {
					if !ip.IsValid() {
						continue
					}
					hosts = append(hosts, ip.String())
				}
			}
		} else {
			hosts = append(hosts, cidr)
		}
	}
	totalTasks := len(hosts)

	go func() {
		for _, host := range hosts {
			tasks <- struct {
				host string
				port string
			}{
				host: host,
				port: port,
			}
		}
		close(tasks)
	}()

	for i := 0; i < n; i++ {
		go func() {
			for task := range tasks {
				var delay time.Duration
				var successes int
				for j := 0; j < try; j++ {
					start := time.Now()
					err := Check(task.host, task.port)
					if err == nil {
						delay += time.Since(start)
						successes++
					}
				}
				if successes > 0 {
					delay = delay / time.Duration(successes)
				}
				results <- struct {
					host      string
					port      string
					delay     time.Duration
					successes int
				}{
					host:      task.host,
					port:      task.port,
					delay:     delay,
					successes: successes,
				}
			}
		}()
	}

	resultsSlice := make([]struct {
		host      string
		port      string
		delay     time.Duration
		successes int
	}, 0)
	for i := 0; i < totalTasks; i++ {
		result := <-results
		if result.successes > 0 {
			resultsSlice = append(resultsSlice, result)
		}
		fmt.Printf("\r%d/%d", i+1, totalTasks)
	}

	sort.Slice(resultsSlice, func(i, j int) bool {
		if resultsSlice[i].successes != resultsSlice[j].successes {
			return resultsSlice[i].successes > resultsSlice[j].successes
		}
		return resultsSlice[i].delay < resultsSlice[j].delay
	})

	f, err := os.Create(out)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, r := range resultsSlice {
		fmt.Fprintf(w, "%s %v %d\n", net.JoinHostPort(r.host, r.port), r.delay, r.successes)
	}
	w.Flush()
}

func GenerateIPv6Addresses(cidr string, count uint64) ([]net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR string: %w", err)
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 128 {
		return nil, fmt.Errorf("not an IPv6 CIDR")
	}

	hostBits := uint(bits - ones)
	totalAddresses := new(big.Int).Lsh(big.NewInt(1), hostBits)

	requestedCountBig := new(big.Int).SetUint64(count)

	var result []net.IP

	if requestedCountBig.Cmp(totalAddresses) >= 0 {
		startIPNum := big.NewInt(0).SetBytes(ipNet.IP.To16())

		for i := big.NewInt(0); i.Cmp(totalAddresses) < 0; i.Add(i, big.NewInt(1)) {
			currentIPNum := big.NewInt(0).Add(startIPNum, i)
			ipBytes := currentIPNum.Bytes()
			paddedIPBytes := make([]byte, 16)
			copy(paddedIPBytes[16-len(ipBytes):], ipBytes)
			result = append(result, net.IP(paddedIPBytes))
		}
	} else {
		rngReader := rand.Reader

		uniqueIPs := make(map[string]struct{})

		networkIPNum := big.NewInt(0).SetBytes(ipNet.IP.To16())

		for uint64(len(uniqueIPs)) < count {
			randomHostNum, _ := rand.Int(rngReader, totalAddresses)

			generatedIPNum := big.NewInt(0).Add(networkIPNum, randomHostNum)

			ipBytes := generatedIPNum.Bytes()
			paddedIPBytes := make([]byte, 16)
			copy(paddedIPBytes[16-len(ipBytes):], ipBytes)
			generatedIP := net.IP(paddedIPBytes)

			// if ipNet.Contains(generatedIP) {
			ipString := generatedIP.String()
			if _, exists := uniqueIPs[ipString]; !exists {
				uniqueIPs[ipString] = struct{}{}
				result = append(result, generatedIP)
			}
			// }
		}
	}

	return result, nil
}
