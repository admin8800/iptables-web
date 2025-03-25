package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	SSHUser    = "root"
	SSHPort    = 22
	ConfigPath = "/home/port_%s.txt"
)

var (
	sshClient   *ssh.Client
	publicIP    string
	reconnectCh = make(chan bool, 1)
)

func main() {
	// 定义命令行参数
	var remoteHost, remotePassword string
	flag.StringVar(&remoteHost, "host", "", "远程主机地址 (必须)")
	flag.StringVar(&remotePassword, "password", "", "远程主机密码 (必须)")
	flag.Parse()

	if remoteHost == "" || remotePassword == "" {
		fmt.Println("错误：必须指定主机地址和密码")
		fmt.Println("用法示例：")
		fmt.Println("  sudo ./iptables-copy -host 192.168.1.100 -password yourpassword")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// 获取公网IP
	var err error
	publicIP, err = getPublicIP()
	if err != nil {
		log.Fatalf("获取公网IP失败: %v", err)
	}
	log.Printf("当前公网IP: %s", publicIP)

	// 初始化SSH连接
	initSSHConnection(remoteHost, remotePassword)

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动规则变更监听
	go monitorRules()

	// 主循环
	for {
		select {
		case <-sigChan:
			log.Println("接收到终止信号，退出程序")
			if sshClient != nil {
				sshClient.Close()
			}
			return
		case <-reconnectCh:
			log.Println("尝试重新连接SSH...")
			time.Sleep(5 * time.Second)
			initSSHConnection(remoteHost, remotePassword)
		}
	}
}

func getPublicIP() (string, error) {
	resp, err := http.Get("http://ipinfo.io/ip")
	if err != nil {
		return "", fmt.Errorf("获取公网IP请求失败: %v", err)
	}
	defer resp.Body.Close()

	ipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取公网IP响应失败: %v", err)
	}

	return strings.TrimSpace(string(ipBytes)), nil
}

func initSSHConnection(host, password string) {
	if sshClient != nil {
		sshClient.Close()
	}

	sshConfig := &ssh.ClientConfig{
		User: SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	var err error
	var retries int
	maxRetries := 5

	for retries < maxRetries {
		sshClient, err = ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, SSHPort), sshConfig)
		if err == nil {
			log.Println("SSH连接成功")
			return
		}

		retries++
		log.Printf("SSH连接失败(尝试 %d/%d): %v", retries, maxRetries, err)
		if retries < maxRetries {
			time.Sleep(5 * time.Second)
		}
	}

	log.Printf("SSH连接失败，达到最大重试次数 %d", maxRetries)
	reconnectCh <- true
}

func monitorRules() {
	// 使用轮询方式检查规则变更
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var lastRulesHash string

	for range ticker.C {
		rules, err := getFormattedRules()
		if err != nil {
			log.Printf("获取规则失败: %v", err)
			continue
		}

		currentHash := hashRules(rules)
		if currentHash != lastRulesHash {
			lastRulesHash = currentHash
			log.Println("检测到iptables规则变更")
			if err := sendRulesToRemote(rules); err != nil {
				log.Printf("发送规则到远程失败: %v", err)
			}
		}
	}
}

func hashRules(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

func getFormattedRules() ([]byte, error) {
	cmd := exec.Command("iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("执行iptables命令失败: %v", err)
	}

	var formatted bytes.Buffer
	formatted.WriteString("机器端口\t\t目标IP和端口\n")

	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		if !strings.Contains(line, "DNAT") {
			continue
		}

		localPort := extractField(line, "dpt:")
		target := extractField(line, "to:")
		if localPort != "" && target != "" {
			formatted.WriteString(fmt.Sprintf("%s\t\t%s\n", localPort, target))
		}
	}

	return formatted.Bytes(), nil
}

func extractField(line, prefix string) string {
	start := strings.Index(line, prefix)
	if start == -1 {
		return ""
	}
	start += len(prefix)
	end := strings.IndexAny(line[start:], " \t\n")
	if end == -1 {
		return line[start:]
	}
	return line[start : start+end]
}

func sendRulesToRemote(rules []byte) error {
	if sshClient == nil {
		return fmt.Errorf("SSH连接未建立")
	}

	remoteFilePath := fmt.Sprintf(ConfigPath, publicIP)

	session, err := sshClient.NewSession()
	if err != nil {
		reconnectCh <- true
		return fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("获取标准输入管道失败: %v", err)
	}

	if err := session.Start(fmt.Sprintf("cat > %s", remoteFilePath)); err != nil {
		return fmt.Errorf("启动远程命令失败: %v", err)
	}

	if _, err := io.Copy(stdin, bytes.NewReader(rules)); err != nil {
		return fmt.Errorf("写入规则数据失败: %v", err)
	}

	if err := stdin.Close(); err != nil {
		return fmt.Errorf("关闭管道失败: %v", err)
	}

	if err := session.Wait(); err != nil {
		reconnectCh <- true
		return fmt.Errorf("远程命令执行失败: %v", err)
	}

	log.Printf("规则已成功保存到远程: %s", remoteFilePath)
	return nil
}