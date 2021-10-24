package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/olekukonko/tablewriter"
	"golang.org/x/crypto/ssh"
)

var (
	hostAddr   = flag.String("h", "", "host address")
	user       = flag.String("u", "root", "username")
	sshKeyPath = flag.String("i", "", "ssh key filename")
	sshPass    = flag.String("p", "", "password")
	configFile = flag.String("c", "", "config file")

	vendorRegex    = regexp.MustCompile(`^ID="?(.*)"?$`)
	nameRegex      = regexp.MustCompile(`^NAME="?(.*)"?$`)
	versionIDRegex = regexp.MustCompile(`^VERSION_ID="?(.*)"?$`)
	processRegex   = regexp.MustCompile(`\s?(\S+)\s?`)
)

type Config struct {
	Servers []ServerInformation `json:"servers"`
}

type ServerInformation struct {
	HostAddress string `json:"host_address"`
	User        string `json:"user"`
	SSHKeyPath  string `json:"ssh_key_path"`
	SSHKeyPass  string `json:"ssh_key_pass"`
}

type HostInformation struct {
	HostAddr  string                `json:"host_addr"`
	Name      string                `json:"name,omitempty"`
	Vendor    string                `json:"vendor,omitempty"`
	Version   string                `json:"version,omitempty"`
	Processes []*ProcessInformation `json:"processes,omitempty"`
}

type ProcessInformation struct {
	User    string `json:"user"`
	Pid     string `json:"pid"`
	CPU     string `json:"cpu"`
	MEM     string `json:"mem"`
	Command string `json:"command"`
}

func DialWithKey(addr string, user string, keyfile string, password string) (*ssh.Client, error) {
	var keyBytes []byte
	var err error

	keyBytes, err = ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	var signer ssh.Signer

	if len(password) > 0 {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(password))
		if err != nil {
			return nil, err
		}
	} else {
		signer, err = ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		}),
		BannerCallback: func(message string) error {
			return nil
		},
	}

	var client *ssh.Client

	client, err = ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func getConfigFile(filename string) (Config, error) {
	var config Config
	var configBytes []byte
	var err error

	configBytes, err = ioutil.ReadFile(filename)
	if err != nil {
		return Config{}, err
	}

	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}

func collectData(addr string, user string, keyfile string, password string) (*HostInformation, error) {
	var osInfo = &HostInformation{}
	var client *ssh.Client
	var err error

	if len(keyfile) == 0 {
		var temp string

		temp, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}

		keyfile = filepath.Join(temp, ".ssh/id_rsa")
	}

	client, err = DialWithKey(addr, user, keyfile, password)
	if err != nil {
		return nil, err
	}

	defer client.Close()

	err = parseOSInfo(client, osInfo)
	if err != nil {
		return nil, err
	}

	err = parseProcessList(client, osInfo)
	if err != nil {
		return nil, err
	}

	return osInfo, nil
}

func parseOSInfo(client *ssh.Client, osInfo *HostInformation) error {
	var buffer *bytes.Buffer
	var matches []string
	var err error

	buffer, err = runCommand(client, "cat /etc/os-release")
	if err != nil {
		return err
	}

	s := bufio.NewScanner(buffer)
	for s.Scan() {
		matches = versionIDRegex.FindStringSubmatch(s.Text())
		if len(matches) > 0 {
			osInfo.Version = strings.Trim(matches[1], `"`)
			continue
		}

		matches = nameRegex.FindStringSubmatch(s.Text())
		if len(matches) > 0 {
			osInfo.Name = strings.Trim(matches[1], `"`)
			continue
		}

		matches = vendorRegex.FindStringSubmatch(s.Text())
		if len(matches) > 0 {
			osInfo.Vendor = strings.Trim(matches[1], `"`)
			continue
		}
	}

	return nil
}

func parseProcessList(client *ssh.Client, osInfo *HostInformation) error {
	var buffer *bytes.Buffer
	var err error

	buffer, err = runCommand(client, "ps aux")
	if err != nil {
		return err
	}

	var data = strings.Split(buffer.String(), "\n")

	for _, line := range data {
		var colData = processRegex.FindAllStringSubmatch(line, -1)

		if len(colData) == 0 {
			continue
		}

		if len(colData) >= 11 && !strings.HasPrefix(colData[10][1], "[") && colData[1][1] != "PID" {
			osInfo.Processes = append(osInfo.Processes, &ProcessInformation{
				User:    colData[0][1],
				Pid:     colData[1][1],
				CPU:     colData[2][1],
				MEM:     colData[3][1],
				Command: colData[10][1],
			})
		}
	}

	return nil
}

func runCommand(client *ssh.Client, command string) (*bytes.Buffer, error) {
	var session *ssh.Session
	var err error

	session, err = client.NewSession()
	if err != nil {
		return nil, err
	}

	defer session.Close()

	var buffer = bytes.NewBuffer(nil)

	session.Stdout = buffer

	err = session.Run(command)
	if err != nil {
		return nil, err
	}

	return buffer, nil
}

func main() {
	var allData []*HostInformation
	var err error

	flag.Parse()

	if len(*configFile) > 0 {
		var configInfo Config
		var hostInfo *HostInformation

		configInfo, err = getConfigFile(*configFile)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		for _, serverInfo := range configInfo.Servers {
			hostInfo, err = collectData(serverInfo.HostAddress, serverInfo.User, serverInfo.SSHKeyPath, serverInfo.SSHKeyPass)
			if err != nil {
				fmt.Println(err.Error())
			} else {
				hostInfo.HostAddr = serverInfo.HostAddress
				allData = append(allData, hostInfo)
			}
		}
	} else {
		var hostInfo *HostInformation

		hostInfo, err = collectData(*hostAddr, *user, *sshKeyPath, *sshPass)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		hostInfo.HostAddr = *hostAddr

		allData = append(allData, hostInfo)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Host", "OS Name", "OS Vendor", "OS Version", "Process User", "Process ID", "Process CPU", "Process MEM", "Process Command"})
	for _, osInfo := range allData {
		for _, process := range osInfo.Processes {
			table.Append([]string{osInfo.HostAddr, osInfo.Name, osInfo.Vendor, osInfo.Version, process.User, process.Pid, process.CPU, process.MEM, process.Command})
		}
	}
	table.Render()
}
