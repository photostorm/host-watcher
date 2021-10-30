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
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nsf/termbox-go"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/crypto/ssh"
)

var (
	hostAddr       = flag.String("h", "", "host address")
	user           = flag.String("u", "root", "username")
	sshKeyPath     = flag.String("i", "", "ssh key filename")
	sshPass        = flag.String("p", "", "password")
	configFile     = flag.String("c", "", "config file")
	interactive    = flag.Bool("it", false, "interactive terminal")
	updateTime     = flag.Duration("d", 1*time.Minute, "how often to update the results (only with interactive terminal)")
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

type UI struct {
	infoText     string
	tableScrollX int
	tableScrollY int
	tableColumns []string
	tableRows    []UITableRow
	selectables  []string
	selection    string
	uiEvents     chan UITermEvent
	terminate    chan struct{}
	done         chan struct{}
	updateTime   time.Duration
}

type UITermEvent struct {
	event termbox.Event
	done  chan struct{}
}

type UITableRow struct {
	id    string
	cells []string
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

func NewUI(tableRows []UITableRow, updateTime time.Duration) (*UI, error) {
	err := termbox.Init()
	if err != nil {
		return nil, err
	}

	u := &UI{
		infoText: fmt.Sprintf("last update: %s",
			time.Now().Format("Jan 2 15:04:05")),
		tableColumns: []string{
			"host",
			"os-name",
			"os-vendor",
			"os-version",
			"process-user",
			"process-id",
			"process-cpu",
			"process-mem",
			"process-command",
		},
		tableRows:  tableRows,
		uiEvents:   make(chan UITermEvent),
		terminate:  make(chan struct{}),
		done:       make(chan struct{}),
		updateTime: updateTime,
	}

	u.selectables = nil

	for _, col := range u.tableColumns {
		u.selectables = append(u.selectables, "col_"+col)
	}

	for _, row := range u.tableRows {
		u.selectables = append(u.selectables, "row_"+row.id)
	}

	if u.selection == "" {
		u.selection = u.selectables[0]
	}

	return u, nil
}

func (u *UI) Run(wg *sync.WaitGroup, sigMain chan os.Signal) {
	u.draw()

	go u.pollEvents()

	periodicUpdateTicker := time.NewTicker(u.updateTime)
	defer periodicUpdateTicker.Stop()

	periodicRedrawTicker := time.NewTicker(2 * time.Second)
	defer periodicRedrawTicker.Stop()

outer:
	for {
		select {
		case <-periodicRedrawTicker.C:
			u.draw()
			break
		case <-periodicUpdateTicker.C:
			var tableRows []UITableRow
			var allData []*HostInformation
			var err error

			allData, err = collectAllData()
			if err == nil {
				for _, osInfo := range allData {
					for _, process := range osInfo.Processes {
						tableRows = append(tableRows, UITableRow{
							id: osInfo.HostAddr + process.Pid,
							cells: []string{
								osInfo.HostAddr, osInfo.Name, osInfo.Vendor, osInfo.Version,
								process.User, process.Pid, process.CPU, process.MEM, process.Command,
							},
						})
					}
				}

				u.tableRows = tableRows
				u.infoText = fmt.Sprintf("last update: %s",
					time.Now().Format("Jan 2 15:04:05"))
			}
			break
		case req := <-u.uiEvents:
			switch req.event.Type {
			case termbox.EventKey:
				switch req.event.Key {
				case termbox.KeyEsc, termbox.KeyCtrlC, termbox.KeyCtrlX:
					break outer
				case termbox.KeyArrowLeft:
					u.tableScrollX += 1
					u.draw()
					break
				case termbox.KeyArrowRight:
					u.tableScrollX -= 1
					u.draw()
					break
				case termbox.KeyArrowUp:
					u.updateYIndex(-1)
					u.draw()
					break
				case termbox.KeyArrowDown:
					u.updateYIndex(1)
					u.draw()
					break
				case termbox.KeyPgup:
					_, termHeight := termbox.Size()
					u.updateYIndex(-(termHeight - 9))
					u.draw()
					break
				case termbox.KeyPgdn:
					_, termHeight := termbox.Size()
					u.updateYIndex(termHeight - 9)
					u.draw()
					break
				default:
					switch req.event.Ch {
					case 'q', 'Q':
						break outer
					}
					break
				}
			case termbox.EventResize:
				u.draw()
				break
			case termbox.EventError:
				panic(req.event.Err)
			}

			close(req.done)
		case <-sigMain:
			break outer
		case <-u.terminate:
			break outer
		}
	}

	//termbox.Interrupt()
	termbox.Close()

	close(u.uiEvents)
	close(u.done)

	wg.Done()
}

func (u *UI) Close() {
	close(u.terminate)
	<-u.done
}

func (u *UI) pollEvents() {
	for {
		tevt := termbox.PollEvent()
		if tevt.Type == termbox.EventInterrupt || tevt.Type == termbox.EventError {
			break
		}

		done := make(chan struct{})
		u.uiEvents <- UITermEvent{tevt, done}
		<-done
	}
}

func (u *UI) findSelectionIndex() int {
	for i, sel := range u.selectables {
		if sel == u.selection {
			return i
		}
	}

	return 0
}

func (u *UI) updateYIndex(value int) {
	oldIndex := u.findSelectionIndex()

	newIndex := oldIndex + value

	if newIndex >= len(u.selectables) {
		newIndex = len(u.selectables) - 1
	} else if newIndex < 0 {
		newIndex = 0
	}

	if newIndex >= 0 && len(u.selectables) >= 1 {
		u.selection = u.selectables[newIndex]
	}
}

func (u *UI) draw() {
	termbox.Clear(termbox.ColorBlack, termbox.ColorBlack)

	termWidth, termHeight := termbox.Size() // must be called after Clear()

	u.drawRect(0, 0, termWidth, 3)

	u.drawClippedText(1, termWidth-2, 1, 1, u.infoText,
		termbox.ColorWhite, termbox.ColorBlack)

	u.drawRect(0, 3, termWidth, termHeight-3)

	u.drawScrollableTable(1, 4, termWidth-2, termHeight-5,
		u.selection, u.tableColumns, u.tableRows, &u.tableScrollX, &u.tableScrollY)

	_ = termbox.Flush()
}

func (u *UI) drawRect(startX int, startY int, width int, height int) {
	endX := startX + width - 1
	endY := startY + height - 1

	termbox.SetCell(startX, startY, 0x250C, termbox.ColorWhite, termbox.ColorBlack)
	termbox.SetCell(endX, startY, 0x2510, termbox.ColorWhite, termbox.ColorBlack)
	termbox.SetCell(startX, endY, 0x2514, termbox.ColorWhite, termbox.ColorBlack)
	termbox.SetCell(endX, endY, 0x2518, termbox.ColorWhite, termbox.ColorBlack)

	for x := startX + 1; x < endX; x++ {
		termbox.SetCell(x, startY, 0x2500, termbox.ColorWhite, termbox.ColorBlack)
		termbox.SetCell(x, endY, 0x2500, termbox.ColorWhite, termbox.ColorBlack)
	}

	for y := startY + 1; y < endY; y++ {
		termbox.SetCell(startX, y, 0x2502, termbox.ColorWhite, termbox.ColorBlack)
		termbox.SetCell(endX, y, 0x2502, termbox.ColorWhite, termbox.ColorBlack)
	}
}

func (u *UI) drawClippedText(startX, endX, x, y int, text string, fg, bg termbox.Attribute) {
	for _, r := range text {
		if x >= startX && x <= endX {
			termbox.SetCell(x, y, r, fg, bg)
		}

		x++
	}
}

func (u *UI) findSelectionY(selection string, rows []UITableRow) int {
	if strings.HasPrefix(selection, "row_") {
		for i, row := range rows {
			if selection == "row_"+row.id {
				return i
			}
		}
	}

	return 0
}

func (u *UI) drawScrollableTable(startX int, startY int, width int, height int, selection string, columns []string,
	rows []UITableRow, scrollX *int, scrollY *int) {
	endX := startX + width - 1
	endY := startY + height - 1

	colWidths := make([]int, len(columns))
	for i, col := range columns {
		if colWidths[i] < len(col)+2 {
			colWidths[i] = len(col) + 2
		}
	}

	for _, row := range rows {
		for i, cell := range row.cells {
			if colWidths[i] < len(cell) {
				colWidths[i] = len(cell)
			}
		}
	}

	tableWidth := 0

	for i := range columns {
		tableWidth += colWidths[i] + 2
	}

	tableHeight := 2 + len(rows)

	xMin := width - tableWidth - 1
	if *scrollX < xMin {
		*scrollX = xMin
	}

	xMax := 0
	if *scrollX > xMax {
		*scrollX = xMax
	}

	selectionY := u.findSelectionY(selection, rows)

	yMax := height - 4 - selectionY
	if *scrollY > yMax {
		*scrollY = yMax
	}
	yMin := -selectionY
	if *scrollY < yMin {
		*scrollY = yMin
	}

	u.drawScrollbar(true, endX, startY, height, tableHeight, *scrollY)
	u.drawScrollbar(false, endY, startX, width, tableWidth, *scrollX)

	endX -= 1
	endY -= 1

	x := startX + *scrollX

	for i, col := range columns {
		fg := termbox.ColorWhite
		bg := termbox.ColorBlack

		if selection == "col_"+col {
			fg = termbox.ColorBlack
			bg = termbox.ColorWhite
		}

		u.drawClippedText(startX, endX, x, startY, col, fg, bg)
		x += colWidths[i] + 2
	}

	y := startY + 2 + *scrollY

	for _, row := range rows {
		fg := termbox.ColorWhite
		bg := termbox.ColorBlack

		if selection == "row_"+row.id {
			fg = termbox.ColorBlack
			bg = termbox.ColorWhite
		}

		if y >= (startY+2) && y <= endY {
			x := startX + *scrollX

			for i, cell := range row.cells {
				u.drawClippedText(startX, endX, x, y, cell, fg, bg)
				x += colWidths[i] + 2
			}
		}

		y += 1
	}
}

func (u *UI) drawScrollbar(vertical bool, fixedCoord int, start int, screenSize int, pageSize int, cur int) {
	scrollbarMaxSize := screenSize - 1
	scrollbarSize := scrollbarMaxSize

	if pageSize > scrollbarMaxSize {
		scrollbarSize = scrollbarSize * scrollbarMaxSize / pageSize
	}

	scrollZone := scrollbarMaxSize - scrollbarSize
	min := scrollbarMaxSize - pageSize

	if min != 0 {
		start += scrollZone - scrollZone*(cur-min)/(-min)
	}

	if vertical {
		for y := start; y < (start + scrollbarSize); y++ {
			termbox.SetCell(fixedCoord, y, 0x2588, termbox.ColorBlue, termbox.ColorBlack)
		}
	} else {
		for x := start; x < (start + scrollbarSize); x++ {
			termbox.SetCell(x, fixedCoord, 0x2585, termbox.ColorBlue, termbox.ColorBlack)
		}
	}
}

func collectAllData() ([]*HostInformation, error) {
	var allData []*HostInformation
	var err error

	if len(*configFile) > 0 {
		var configInfo Config
		var hostInfo *HostInformation

		configInfo, err = getConfigFile(*configFile)
		if err != nil {
			return nil, err
		}

		for _, serverInfo := range configInfo.Servers {
			hostInfo, err = collectData(serverInfo.HostAddress, serverInfo.User, serverInfo.SSHKeyPath, serverInfo.SSHKeyPass)
			if err == nil {
				hostInfo.HostAddr = serverInfo.HostAddress
				allData = append(allData, hostInfo)
			}
		}
	} else {
		var hostInfo *HostInformation

		hostInfo, err = collectData(*hostAddr, *user, *sshKeyPath, *sshPass)
		if err != nil {
			return nil, err
		}

		hostInfo.HostAddr = *hostAddr

		allData = append(allData, hostInfo)
	}

	return allData, nil
}

func main() {
	var allData []*HostInformation
	var err error

	flag.Parse()

	allData, err = collectAllData()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if *interactive {
		var wg sync.WaitGroup
		var collectorUI *UI

		sigMain := make(chan os.Signal)
		signal.Notify(sigMain, os.Interrupt)

		var tableRows []UITableRow

		for _, osInfo := range allData {
			for _, process := range osInfo.Processes {
				tableRows = append(tableRows, UITableRow{
					id: osInfo.HostAddr + process.Pid,
					cells: []string{
						osInfo.HostAddr, osInfo.Name, osInfo.Vendor, osInfo.Version,
						process.User, process.Pid, process.CPU, process.MEM, process.Command,
					},
				})
			}
		}

		collectorUI, err = NewUI(tableRows, *updateTime)
		if err == nil {
			wg.Add(1)
			go collectorUI.Run(&wg, sigMain)
		}

		wg.Wait()
	} else {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Host", "OS Name", "OS Vendor", "OS Version", "Process User", "Process ID", "Process CPU", "Process MEM", "Process Command"})
		for _, osInfo := range allData {
			for _, process := range osInfo.Processes {
				table.Append([]string{osInfo.HostAddr, osInfo.Name, osInfo.Vendor, osInfo.Version, process.User, process.Pid, process.CPU, process.MEM, process.Command})
			}
		}
		table.Render()
	}
}
