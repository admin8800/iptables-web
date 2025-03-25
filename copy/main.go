package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
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
	// 验证环境变量
	remoteHost := os.Getenv("IPTABLES_REMOTE_HOST")
	remotePassword := os.Getenv("IPTABLES_REMOTE_PASSWORD")

	if remoteHost == "" || remotePassword == "" {
		log.Fatal("必须设置 IPTABLES_REMOTE_HOST 和 IPTABLES_REMOTE_PASSWORD 环境变量")
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

	// 启动Netlink监听
	go startNetlinkListener()

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
			time.Sleep(5 * time.Second) // 等待5秒后重试
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 禁用主机密钥检查
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

func startNetlinkListener() {
	for {
		conn := newNetlinkConn()
		log.Println("开始监听iptables规则变更...")

		if err := subscribeNetfilterEvents(conn); err != nil {
			log.Printf("订阅Netfilter事件失败: %v", err)
			conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		for {
			msgs, err := conn.Receive()
			if err != nil {
				log.Printf("接收Netlink消息错误: %v", err)
				break
			}

			for _, msg := range msgs {
				if msg.Header.Type == nl.NLMSG_ERROR {
					log.Printf("Netlink错误消息: %v", msg)
					continue
				}

				if isRulesChangeEvent(msg) {
					log.Println("检测到iptables规则变更")
					if err := handleRulesChange(); err != nil {
						log.Printf("处理规则变更失败: %v", err)
					}
				}
			}
		}

		conn.Close()
		time.Sleep(5 * time.Second)
	}
}

func newNetlinkConn() *nl.NetlinkSocket {
	conn, err := nl.Subscribe(syscall.NETLINK_NETFILTER)
	if err != nil {
		log.Fatalf("创建Netlink连接失败: %v", err)
	}
	return conn
}

func subscribeNetfilterEvents(conn *nl.NetlinkSocket) error {
	req := nl.NewNetlinkRequest(nl.NFNL_SUBSYS_IPTABLES<<8|nl.IPTM_MSG_GET, nl.NLM_F_DUMP)
	_, err := conn.Execute(req)
	return err
}

func isRulesChangeEvent(msg *nl.NetlinkMessage) bool {
	return msg.Header.Type&0xFF == nl.IPTM_MSG_NEW ||
		msg.Header.Type&0xFF == nl.IPTM_MSG_DEL
}

func handleRulesChange() error {
	rules, err := getFormattedRules()
	if err != nil {
		return fmt.Errorf("获取规则失败: %v", err)
	}

	if err := sendRulesToRemote(rules); err != nil {
		return fmt.Errorf("发送规则到远程失败: %v", err)
	}

	return nil
}

func getFormattedRules() ([]byte, error) {
	cmd := exec.Command("sudo", "iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
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

	// 生成带公网IP的文件名
	remoteFilePath := fmt.Sprintf(ConfigPath, publicIP)

	session, err := sshClient.NewSession()
	if err != nil {
		reconnectCh <- true
		return fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	go func() {
		stdin, err := session.StdinPipe()
		if err != nil {
			log.Printf("获取标准输入管道失败: %v", err)
			return
		}
		defer stdin.Close()

		cmd := fmt.Sprintf("cat > %s", remoteFilePath)
		if err := session.Start(cmd); err != nil {
			log.Printf("启动远程命令失败: %v", err)
			reconnectCh <- true
			return
		}

		if _, err := io.Copy(stdin, bytes.NewReader(rules)); err != nil {
			log.Printf("写入规则数据失败: %v", err)
			return
		}

		if err := stdin.Close(); err != nil {
			log.Printf("关闭管道失败: %v", err)
		}

		if err := session.Wait(); err != nil {
			log.Printf("远程命令执行失败: %v", err)
			reconnectCh <- true
		} else {
			log.Printf("规则已成功保存到远程: %s", remoteFilePath)
		}
	}()

	return nil
}