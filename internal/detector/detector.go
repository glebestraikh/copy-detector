package detector

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	bufferSize      = 128
	sendInterval    = 2 * time.Second
	nodeTimeout     = 8 * time.Second
	cleanupInterval = 5 * time.Second
)

type Message struct {
	ID uuid.UUID `json:"id"`
}

type NodeInfo struct {
	ID      uuid.UUID
	Address *net.UDPAddr
	Status  string
}

type InterfaceInfo struct {
	Interface *net.Interface
	Type      string
}

type Detector struct {
	id              uuid.UUID
	addr            *net.UDPAddr
	iface           *net.Interface
	nodes           map[uuid.UUID]*net.UDPAddr
	lastSeen        map[uuid.UUID]time.Time
	mu              sync.RWMutex
	network         string
	tableUpdateChan chan bool
}

func initLogging() {
	file, err := os.OpenFile("detector.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	log.SetOutput(file)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
}

func Start(addr string, port int) {
	initLogging()
	id, _ := uuid.NewUUID()

	addrStr := net.JoinHostPort(addr, strconv.Itoa(port))
	multicastAddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		log.Printf("Failed to resolve UDP address: %v", err)
		return
	}

	if !multicastAddr.IP.IsMulticast() {
		log.Printf("Provided address '%s' is not a valid multicast address", multicastAddr)
		return
	}

	network := "udp4"
	if multicastAddr.IP.To4() == nil {
		network = "udp6"
	}

	detector := &Detector{
		id:              id,
		addr:            multicastAddr,
		nodes:           make(map[uuid.UUID]*net.UDPAddr),
		lastSeen:        make(map[uuid.UUID]time.Time),
		network:         network,
		tableUpdateChan: make(chan bool, 100),
	}

	ifi, err := detector.selectMulticastInterface()
	if err != nil {
		log.Printf("Failed to select multicast interface: %v", err)
		return
	}
	detector.iface = ifi

	if network == "udp6" && ifi != nil {
		detector.addr.Zone = ifi.Name
	}

	log.Printf("Starting detector with %s protocol for address %s", network, multicastAddr)
	log.Printf("Using interface: %s", ifi.Name)
	log.Printf("Local Node ID: %s", id.String())

	detector.initTable()

	var waitGroup sync.WaitGroup
	waitGroup.Add(1)

	go detector.sender(&waitGroup)
	go detector.receiver(&waitGroup)
	go detector.cleaner(&waitGroup)
	go detector.tableUpdater(&waitGroup)

	waitGroup.Wait()
}

func (detector *Detector) selectMulticastInterface() (*net.Interface, error) {
	interfaces, err := detector.getAvailableInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get available interfaces: %v", err)
	}

	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no suitable multicast interfaces found for %s", detector.network)
	}

	if len(interfaces) == 1 {
		selected := interfaces[0].Interface
		fmt.Printf("Automatically selected interface: %s\n", selected.Name)
		fmt.Printf("Press Enter to continue...")
		fmt.Scanln()
		detector.clearScreen()
		return selected, nil
	}

	detector.clearScreen()
	fmt.Println("=== Network Interface Selection ===")
	fmt.Printf("Protocol: %s | Multicast Address: %s\n", detector.network, detector.addr.String())
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()

	fmt.Printf("%-5s %-20s %-15s\n", "№", "Interface", "Type")
	fmt.Println(strings.Repeat("-", 50))

	for i, ifaceInfo := range interfaces {
		fmt.Printf("%-5d %-20s %-15s\n",
			i+1, ifaceInfo.Interface.Name, ifaceInfo.Type)
	}

	fmt.Println(strings.Repeat("-", 50))
	fmt.Print("\nSelect interface (1-", len(interfaces), ") or 0 for auto-select: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read user input: %v", err)
	}

	choice, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil {
		return nil, fmt.Errorf("invalid input: %v", err)
	}

	var selectedInterface *net.Interface

	if choice == 0 {
		selectedInterface = interfaces[0].Interface
		fmt.Printf("Auto-selected interface: %s\n", selectedInterface.Name)
	} else if choice >= 1 && choice <= len(interfaces) {
		selectedInterface = interfaces[choice-1].Interface
		fmt.Printf("Selected interface: %s\n", selectedInterface.Name)
	} else {
		return nil, fmt.Errorf("invalid choice: %d", choice)
	}

	fmt.Printf("Press Enter to continue...")
	fmt.Scanln()
	detector.clearScreen()

	return selectedInterface, nil
}

func (detector *Detector) getAvailableInterfaces() ([]InterfaceInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var suitable []InterfaceInfo

	for _, ifi := range interfaces {
		if ifi.Flags&(net.FlagUp|net.FlagMulticast) != (net.FlagUp|net.FlagMulticast) ||
			ifi.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}

		var hasIPv4, hasIPv6 bool

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() {
				continue
			}

			if ipnet.IP.To4() != nil {
				hasIPv4 = true
			} else {
				hasIPv6 = true
			}
		}

		var ifaceType string
		var isCompatible bool

		if detector.network == "udp4" && hasIPv4 {
			isCompatible = true
			ifaceType = "IPv4"
		} else if detector.network == "udp6" && hasIPv6 {
			isCompatible = true
			ifaceType = "IPv6"
		}

		if hasIPv4 && hasIPv6 {
			ifaceType = "IPv4/IPv6"
		}

		if isCompatible {
			suitable = append(suitable, InterfaceInfo{
				Interface: &ifi,
				Type:      ifaceType,
			})
		}
	}

	sort.Slice(suitable, func(i, j int) bool {
		return suitable[i].Interface.Name < suitable[j].Interface.Name
	})

	return suitable, nil
}

func (detector *Detector) sender(waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	conn, err := net.DialUDP(detector.network, nil, detector.addr)
	if err != nil {
		log.Printf("Failed to start UDP sender to %v: %v", detector.addr, err)
		return
	}
	defer conn.Close()

	jsonMsg, _ := json.Marshal(Message{detector.id})

	for {
		if _, err := conn.Write(jsonMsg); err != nil {
			log.Printf("Failed to send UDP message: %v", err)
		}
		time.Sleep(sendInterval)
	}
}

func (detector *Detector) receiver(waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	listener, err := net.ListenMulticastUDP(detector.network, detector.iface, detector.addr)
	if err != nil {
		log.Printf("Failed to start UDP multicast receiver on %v: %v", detector.addr, err)
		return
	}
	defer listener.Close()

	buffer := make([]byte, bufferSize)

	for {
		n, senderAddr, err := listener.ReadFromUDP(buffer)
		if err != nil {
			continue
		}

		var msg Message
		if json.Unmarshal(buffer[:n], &msg) != nil || msg.ID == detector.id {
			continue
		}

		detector.addOrUpdateNode(msg.ID, senderAddr)
	}
}

func (detector *Detector) cleaner(waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	for {
		time.Sleep(cleanupInterval)

		detector.mu.Lock()
		hasChanges := false

		for id, lastTime := range detector.lastSeen {
			if time.Since(lastTime) > nodeTimeout {
				delete(detector.nodes, id)
				delete(detector.lastSeen, id)
				hasChanges = true
			}
		}
		detector.mu.Unlock()

		if hasChanges {
			detector.triggerTableUpdate()
		}
	}
}

func (detector *Detector) addOrUpdateNode(id uuid.UUID, addr *net.UDPAddr) {
	detector.mu.Lock()
	defer detector.mu.Unlock()

	_, exists := detector.nodes[id]
	detector.nodes[id] = addr
	detector.lastSeen[id] = time.Now()

	if !exists {
		detector.triggerTableUpdate()
	}
}

func (detector *Detector) triggerTableUpdate() {
	select {
	case detector.tableUpdateChan <- true:
	default:
	}
}

func (detector *Detector) initTable() {
	detector.clearScreen()
	fmt.Println("=== Network Node Detector ===")
	fmt.Printf("Local ID: %s\n", detector.id.String())
	fmt.Printf("Network: %s | Address: %s | Interface: %s\n",
		detector.network, detector.addr.String(), detector.iface.Name)
	fmt.Println("=" + strings.Repeat("=", 80))
	fmt.Println()
}

func (detector *Detector) tableUpdater(waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	detector.displayTable()

	for range detector.tableUpdateChan {
		detector.displayTable()
	}
}

func (detector *Detector) displayTable() {
	detector.clearScreen()
	detector.mu.RLock()
	nodes := make([]NodeInfo, 0, len(detector.nodes))

	for id, addr := range detector.nodes {
		status := "Online"
		if time.Since(detector.lastSeen[id]) > nodeTimeout {
			status = "Offline"
		}

		nodes = append(nodes, NodeInfo{
			ID:      id,
			Address: addr,
			Status:  status,
		})
	}
	detector.mu.RUnlock()

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Address.String() < nodes[j].Address.String()
	})

	detector.initTable()

	fmt.Printf("%-10s %-20s %-25s %-10s\n",
		"№", "Node ID", "IP:Port", "Status")
	fmt.Println(strings.Repeat("-", 70))

	for i, node := range nodes {
		addrStr := node.Address.String()
		if node.Address.IP.To4() == nil {
			addrStr = fmt.Sprintf("[%s]:%d", node.Address.IP.String(), node.Address.Port)
		}

		nodeID := node.ID.String()[:8] + "..."

		statusSymbol := "🟢"
		if node.Status != "Online" {
			statusSymbol = "..."
		}

		fmt.Printf("%-10d %-20s %-25s %-10s\n",
			i+1, nodeID, addrStr, statusSymbol+" "+node.Status)
	}

	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("Total active nodes: %d", len(nodes))

	detector.clearRemainingLines()

	fmt.Printf("\n\nLast updated: %s", time.Now().Format("15:04:05"))
}

func (detector *Detector) clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to clear screen: %v", err)
	}
}

func (detector *Detector) clearRemainingLines() {
	fmt.Print("\033[J")
}
