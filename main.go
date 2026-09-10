package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	IP      string
	Latency time.Duration
	Colo    string
	Valid   bool
}

// 优选扫描网段：各大厂 SaaS、Enterprise、亚太互联高权重网段
var defaultSubnets = []string{
	"104.16.80.0/20",
	"104.17.64.0/20",
	"104.18.32.0/20",
	"162.159.138.0/24",
	"162.159.144.0/24",
	"172.64.32.0/20",
	"108.162.193.0/24",
	"141.101.64.0/24",
}

// 亚太低延迟核心落地机房白名单
var tier1AsiaColos = map[string]bool{
	"HKG": true, // 香港
	"MFM": true, // 澳门
	"TPE": true, // 台北
	"NRT": true, // 东京成田
	"HND": true, // 东京羽田
	"KIX": true, // 大阪
	"ICN": true, // 首尔
	"SIN": true, // 新加坡
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// 解析 CIDR 网段生成目标 IP 列表（为控制 Runner 负载，每个 /20 网段抽样生成，小网段全量扫描）
func generateIPs(cidr string, sampleRate int) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	count := 0
	for current := ip.Mask(ipnet.Mask); ipnet.Contains(current); incIP(current) {
		count++
		if count%sampleRate == 0 {
			ips = append(ips, current.String())
		}
	}
	return ips, nil
}

// 执行底层 TLS 握手与 SaaS SNI 校验
func probeIP(ctx context.Context, ip string, hostName string, timeout time.Duration) *ScanResult {
	start := time.Now()

	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil
	}
	defer rawConn.Close()

	tlsConfig := &tls.Config{
		ServerName:         hostName,
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil
	}
	defer tlsConn.Close()

	handshakeLatency := time.Since(start)

	// 构造轻量级 GET 请求，探测 /cdn-cgi/trace
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+hostName+"/cdn-cgi/trace", nil)
	if err != nil {
		return nil
	}
	req.Host = hostName
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return tlsConn, nil
			},
		},
		Timeout: timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// 严格剔除 Cloudflare 1000/1034 错误响应
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	colo := "UNKNOWN"
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "colo=") {
			colo = strings.TrimPrefix(line, "colo=")
			break
		}
	}

	return &ScanResult{
		IP:      ip,
		Latency: handshakeLatency,
		Colo:    colo,
		Valid:   true,
	}
}

func main() {
	hostName := flag.String("host", "", "你在 Cloudflare for SaaS 绑定的加速主机名 (例: fast.domain-b.com)")
	concurrency := flag.Int("c", 300, "并发扫描线程数")
	timeoutMs := flag.Int("t", 1200, "连接与握手超时 (毫秒)")
	topLimit := flag.Int("top", 32, "保留的最优 IP 数量")
	flag.Parse()

	if *hostName == "" {
		fmt.Println("[-] 错误: 必须指定 -host 参数 (你的 SaaS 加速域名)")
		os.Exit(1)
	}

	fmt.Printf("[+] 启动 Anycast 扫描引擎 | 目标域名: %s | 并发: %d\n", *hostName, *concurrency)

	var allIPs []string
	for _, subnet := range defaultSubnets {
		sample := 8 // 控制抽样密度，保证在 Runner 10 分钟限额内跑完
		if strings.HasSuffix(subnet, "/24") {
			sample = 1
		}
		ips, err := generateIPs(subnet, sample)
		if err == nil {
			allIPs = append(allIPs, ips...)
		}
	}

	fmt.Printf("[+] 待扫描候选 IP 资产总量: %d\n", len(allIPs))

	jobs := make(chan string, len(allIPs))
	results := make(chan *ScanResult, len(allIPs))
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	timeout := time.Duration(*timeoutMs) * time.Millisecond

	// 启动 Worker 池
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					res := probeIP(ctx, ip, *hostName, timeout)
					if res != nil && res.Valid {
						results <- res
					}
				}
			}
		}()
	}

	for _, ip := range allIPs {
		jobs <- ip
	}
	close(jobs)

	wg.Wait()
	close(results)

	var validResults []*ScanResult
	for r := range results {
		validResults = append(validResults, r)
	}

	// 按照往返时延排序 (从小到大)
	sort.Slice(validResults, func(i, j int) bool {
		return validResults[i].Latency < validResults[j].Latency
	})

	// 导出最优节点文件
	cleanIPFile, _ := os.Create("clean_ips.txt")
	defer cleanIPFile.Close()
	cleanIPWriter := bufio.NewWriter(cleanIPFile)

	csvFile, _ := os.Create("scan_results.csv")
	defer csvFile.Close()
	csvWriter := csv.NewWriter(csvFile)
	_ = csvWriter.Write([]string{"IP", "Latency_MS", "Colo", "Is_Tier1_Asia"})

	count := 0
	fmt.Println("\n[+] 扫描完成，最优 Anycast 节点列表:")
	fmt.Printf("%-18s %-12s %-8s %-10s\n", "IP 地址", "时延", "机房", "近海优先")

	for _, r := range validResults {
		isAsia := tier1AsiaColos[r.Colo]
		_ = csvWriter.Write([]string{
			r.IP,
			fmt.Sprintf("%d", r.Latency.Milliseconds()),
			r.Colo,
			fmt.Sprintf("%t", isAsia),
		})

		// 优先提取近海一级机房，或者整体低延迟节点
		if count < *topLimit {
			_, _ = cleanIPWriter.WriteString(r.IP + "\n")
			fmt.Printf("%-18s %-12d %-8s %-10t\n", r.IP, r.Latency.Milliseconds(), r.Colo, isAsia)
			count++
		}
	}

	_ = cleanIPWriter.Flush()
	csvWriter.Flush()
	fmt.Printf("[+] 结果已导出至 clean_ips.txt 与 scan_results.csv，保留前 %d 个优质 IP\n", count)
}
