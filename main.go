package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/olekukonko/tablewriter"
	"golang.org/x/crypto/ssh"
)

type OS struct {
	Name    string `json:"name,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	Version string `json:"version,omitempty"`
}

var (
	hostAddr   = flag.String("h", "", "host address")
	user       = flag.String("u", "root", "username")
	sshKeyPath = flag.String("i", "", "ssh key filename")
	sshPass    = flag.String("p", "", "password")

	vendorRegex    = regexp.MustCompile(`^ID="?(.*)"?$`)
	nameRegex      = regexp.MustCompile(`^NAME="?(.*)"?$`)
	versionIDRegex = regexp.MustCompile(`^VERSION_ID="?(.*)"?$`)
)

func DialWithKey(addr string, user string, keyfile string) (*ssh.Client, error) {
	var keyBytes []byte
	var err error

	keyBytes, err = ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	var signer ssh.Signer

	signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(*sshPass))
	if err != nil {
		return nil, err
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

func main() {
	var session *ssh.Session
	var client *ssh.Client
	var err error

	flag.Parse()

	if len(*sshKeyPath) == 0 {
		var temp string

		temp, err = os.UserHomeDir()
		if err != nil {
			fmt.Println(err)
			return
		}

		*sshKeyPath = filepath.Join(temp, ".ssh/id_rsa")
	}

	client, err = DialWithKey(*hostAddr, *user, *sshKeyPath)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer client.Close()

	session, err = client.NewSession()
	if err != nil {
		return
	}

	defer session.Close()

	var buffer = bytes.NewBuffer(nil)

	session.Stdout = buffer

	err = session.Run("cat /etc/os-release")
	if err != nil {
		return
	}

	log.Println(buffer.String())

	var matches []string
	var osInfo OS

	s := bufio.NewScanner(buffer)
	for s.Scan() {
		log.Println(s.Text())

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

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Host", "OS Name", "OS Vendor", "OS Version"})
	table.Append([]string{*hostAddr, osInfo.Name, osInfo.Vendor, osInfo.Version})
	table.Render()
}
