package main

import (
	"bytes"
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
	ConfigPath = "/home/%s.json"
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
		fmt.Println("用法示例：")
		fmt.Println("iptables-copy -host 192.168.1.100 -password yourpassword")
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

	checkCmd := exec.Command("ssh-keygen", "-F", host)
	if err := checkCmd.Run(); err == nil {
		cmd := exec.Command("ssh-keygen", "-R", host)
		if err := cmd.Run(); err != nil {
			log.Printf("清除旧的已知主机缓存失败: %v", err)
		} else {
			log.Printf("成功清除旧的已知主机缓存: %s", host)
		}
	} else {
		log.Printf("没有检测到旧的主机缓存: %s", host)
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

		// 修改JSON中的"local_port"键名为公网IP
		modifiedData, err := replaceLocalPortKey(data, publicIP)
		if err != nil {
			log.Printf("修改JSON键名失败: %v", err)
			continue
		}

		if err := sendFileToRemote(modifiedData); err != nil {
			log.Printf("发送文件到远程失败: %v", err)
		}
	}
}

// 将JSON中的"local_port"替换为本机公网IP
func replaceLocalPortKey(data []byte, publicIP string) ([]byte, error) {
	// 使用字符串替换方式处理JSON保留原本结构
	jsonStr := string(data)
	modifiedStr := strings.ReplaceAll(jsonStr, `"local_port"`, fmt.Sprintf(`"%s"`, publicIP))
	
	// 验证修改后的JSON是否有效
	var js map[string]interface{}
	if err := json.Unmarshal([]byte(modifiedStr), &js); err != nil {
		return nil, fmt.Errorf("修改后的JSON验证失败: %v", err)
	}

	return []byte(modifiedStr), nil
}

func sendFileToRemote(fileData []byte) error {
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

	if _, err := io.Copy(stdin, bytes.NewReader(fileData)); err != nil {
		return fmt.Errorf("写入文件数据失败: %v", err)
	}

	if err := stdin.Close(); err != nil {
		return fmt.Errorf("关闭管道失败: %v", err)
	}

	if err := session.Wait(); err != nil {
		reconnectCh <- true
		return fmt.Errorf("远程命令执行失败: %v", err)
	}

	log.Printf("文件已成功保存到远程: %s", remoteFilePath)
	return nil
}