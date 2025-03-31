package main

import (
	"encoding/json"
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
	ConfigPath = "/home/%s.txt" // 使用.txt扩展名
)

var (
	sshClient   *ssh.Client
	publicIP    string
	reconnectCh = make(chan bool, 1)
)

func main() {
	var remoteHost, remotePassword string
	flag.StringVar(&remoteHost, "host", "", "远程主机地址 (必须)")
	flag.StringVar(&remotePassword, "password", "", "远程主机密码 (必须)")
	flag.Parse()

	if remoteHost == "" || remotePassword == "" {
		fmt.Println("错误：必须指定主机地址和密码")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var err error
	publicIP, err = getPublicIP()
	if err != nil {
		log.Fatalf("获取公网IP失败: %v", err)
	}
	log.Printf("当前公网IP: %s", publicIP)

	initSSHConnection(remoteHost, remotePassword)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go monitorFileSync()

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
			time.Sleep(120 * time.Second)
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

	checkCmd := exec.Command("ssh-keygen", "-F", host)
	if err := checkCmd.Run(); err == nil {
		cmd := exec.Command("ssh-keygen", "-R", host)
		if err := cmd.Run(); err != nil {
			log.Printf("清除旧的已知主机缓存失败: %v", err)
		}
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
	maxRetries := 60

	for retries < maxRetries {
		sshClient, err = ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, SSHPort), sshConfig)
		if err == nil {
			log.Println("SSH连接成功")
			return
		}

		retries++
		log.Printf("SSH连接失败(尝试 %d/%d): %v", retries, maxRetries, err)
		time.Sleep(120 * time.Second)
	}

	log.Printf("SSH连接失败，达到最大重试次数 %d", maxRetries)
	reconnectCh <- true
}

func monitorFileSync() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	sourceFile := "/root/data/iptables_rules.json"

	for range ticker.C {
		data, err := os.ReadFile(sourceFile)
		if err != nil {
			log.Printf("读取本地文件失败: %v", err)
			continue
		}

		formattedText, err := convertToTargetFormat(data)
		if err != nil {
			log.Printf("格式转换失败: %v", err)
			continue
		}

		if err := sendFileToRemote(formattedText); err != nil {
			log.Printf("发送文件到远程失败: %v", err)
		}
	}
}

func convertToTargetFormat(data []byte) (string, error) {
	var rules map[string]map[string]interface{}
	if err := json.Unmarshal(data, &rules); err != nil {
		return "", fmt.Errorf("解析JSON失败: %v", err)
	}

	var builder strings.Builder

	for _, rule := range rules {
		localPort, lok := rule["local_port"].(float64)
		targetIP, tok := rule["target_ip"].(string)
		targetPort, pok := rule["target_port"].(float64)

		if lok && tok && pok {
			line := fmt.Sprintf("%-5d\t\t%s:%-5d\n", 
				int(localPort),
				targetIP, int(targetPort))
			builder.WriteString(line)
		}
	}

	return builder.String(), nil
}

func sendFileToRemote(content string) error {
	if sshClient == nil {
		return fmt.Errorf("SSH连接未建立")
	}

	session, err := sshClient.NewSession()
	if err != nil {
		reconnectCh <- true
		return fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	remoteFilePath := fmt.Sprintf(ConfigPath, publicIP)
	cmd := fmt.Sprintf("echo '%s' > %s", strings.ReplaceAll(content, "'", "'\\''"), remoteFilePath)

	if err := session.Run(cmd); err != nil {
		reconnectCh <- true
		return fmt.Errorf("执行远程命令失败: %v", err)
	}

	log.Printf("文件已成功保存到远程: %s", remoteFilePath)
	return nil
}