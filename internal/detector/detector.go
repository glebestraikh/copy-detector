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
	ID       uuid.UUID
	Address  *net.UDPAddr
	LastSeen time.Time
	Status   string
}

type InterfaceInfo struct {
	Interface *net.Interface
	Addresses []string
	Type      string // "ipv4", "ipv6", "both"
}

type Detector struct {
	id              uuid.UUID                  // Уникальный идентификатор этой копии приложения
	addr            *net.UDPAddr               // Адрес мультикаст-группы, к которой мы подключаемся
	iface           *net.Interface             // Выбранный сетевой интерфейс для multicast
	nodes           map[uuid.UUID]*net.UDPAddr // Словарь всех "живых" копий с их UUID и IP-адресами
	lastSeen        map[uuid.UUID]time.Time    // Время последнего сообщения от каждой копии
	mu              sync.RWMutex               // Мьютекс для безопасного доступа к nodes и lastSeen из разных горутин
	network         string                     // "udp4" или "udp6" в зависимости от типа адреса
	tableUpdateChan chan bool                  // Для обновления таблицы
}

func initLogging() {
	// Открываем файл для логов
	file, err := os.OpenFile("detector.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	// Перенаправляем стандартный log в файл
	log.SetOutput(file)

	// Дополнительно можно настроить флаги: время, дата, микросекунды
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
}

func Start(addr string, port int) {
	initLogging()
	id, _ := uuid.NewUUID()

	// net.JoinHostPort соединяет IP и порт в правильную строку адреса, учитывая особенности IPv4 и IPv6
	addrStr := net.JoinHostPort(addr, strconv.Itoa(port))

	// Получаем структуру UDPAddr
	multicastAddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		log.Printf("Failed to resolve UDP address: %v", err)
		return
	}

	// Проверяем, что это действительно мультикаст-адрес
	if !multicastAddr.IP.IsMulticast() {
		log.Printf("Provided address '%s' is not a valid multicast address", multicastAddr)
		return
	}

	// Определяем сетевой протокол на основе типа IP-адреса
	network := determineNetwork(multicastAddr.IP)

	// Создаем детектор
	detector := &Detector{
		id:              id,
		addr:            multicastAddr,
		nodes:           make(map[uuid.UUID]*net.UDPAddr),
		lastSeen:        make(map[uuid.UUID]time.Time),
		network:         network,
		tableUpdateChan: make(chan bool, 100),
	}

	// Выбираем интерфейс интерактивно
	ifi, err := detector.selectMulticastInterface()
	if err != nil {
		log.Printf("Failed to select multicast interface: %v", err)
		return
	}

	detector.iface = ifi

	// Для IPv6 link-local задаем Zone
	if network == "udp6" && ifi != nil {
		detector.addr.Zone = ifi.Name
	}

	log.Printf("Starting detector with %s protocol for address %s", network, multicastAddr)
	log.Printf("Using interface: %s", ifi.Name)
	log.Printf("Local Node ID: %s", id.String())

	// Инициализируем таблицу
	detector.initTable()

	var waitGroup sync.WaitGroup
	waitGroup.Add(1)

	go detector.sender(&waitGroup)
	go detector.receiver(&waitGroup)
	go detector.cleaner(&waitGroup)
	go detector.tableUpdater(&waitGroup)

	waitGroup.Wait()
}

// determineNetwork определяет тип сетевого протокола на основе IP-адреса
func determineNetwork(ip net.IP) string {
	if ip.To4() != nil {
		return "udp4"
	}
	return "udp6"
}

// selectMulticastInterface позволяет пользователю выбрать сетевой интерфейс
func (detector *Detector) selectMulticastInterface() (*net.Interface, error) {
	interfaces, err := detector.getAvailableInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get available interfaces: %v", err)
	}

	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no suitable multicast interfaces found for %s", detector.network)
	}

	// Если только один подходящий интерфейс, используем его автоматически
	if len(interfaces) == 1 {
		selected := interfaces[0].Interface
		fmt.Printf("Automatically selected interface: %s\n", selected.Name)
		fmt.Printf("Press Enter to continue...")
		fmt.Scanln()
		detector.clearScreen()
		return selected, nil
	}

	// Показываем список доступных интерфейсов
	detector.clearScreen()
	fmt.Println("=== Network Interface Selection ===")
	fmt.Printf("Protocol: %s | Multicast Address: %s\n", detector.network, detector.addr.String())
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()

	fmt.Printf("%-5s %-20s %-15s %-30s\n", "№", "Interface", "Type", "IP Addresses")
	fmt.Println(strings.Repeat("-", 100))

	for i, ifaceInfo := range interfaces {
		addresses := strings.Join(ifaceInfo.Addresses, ", ")

		fmt.Printf("%-5d %-20s %-15s %-30s\n",
			i+1,
			ifaceInfo.Interface.Name,
			ifaceInfo.Type,
			addresses)
	}

	fmt.Println(strings.Repeat("-", 100))
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
		// Автоматический выбор - берем первый подходящий
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

// getAvailableInterfaces возвращает список подходящих интерфейсов
func (detector *Detector) getAvailableInterfaces() ([]InterfaceInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var suitable []InterfaceInfo

	for _, ifi := range interfaces {
		if ifi.Flags&net.FlagUp == 0 {
			continue // интерфейс не активен
		}
		if ifi.Flags&net.FlagMulticast == 0 {
			continue // не поддерживает multicast
		}
		if ifi.Flags&net.FlagLoopback != 0 {
			continue // пропускаем loopback
		}

		// Получаем адреса интерфейса
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}

		var addresses []string
		var hasIPv4, hasIPv6 bool

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.IsLoopback() {
					continue
				}

				if ipnet.IP.To4() != nil {
					hasIPv4 = true
					addresses = append(addresses, ipnet.IP.String())
				} else {
					hasIPv6 = true
					addresses = append(addresses, ipnet.IP.String())
				}
			}
		}

		// Проверяем совместимость с требуемым протоколом
		var isCompatible bool
		var ifaceType string

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

		if isCompatible && len(addresses) > 0 {
			suitable = append(suitable, InterfaceInfo{
				Interface: &ifi,
				Addresses: addresses,
				Type:      ifaceType,
			})
		}
	}

	// Сортируем интерфейсы по имени для стабильного порядка
	sort.Slice(suitable, func(i, j int) bool {
		return suitable[i].Interface.Name < suitable[j].Interface.Name
	})

	return suitable, nil
}

func (detector *Detector) sender(waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	// Получаем объект для отправки UDP-пакетов с указанием конкретной версии протокола
	conn, err := net.DialUDP(detector.network, nil, detector.addr)
	if err != nil {
		log.Printf("Failed to start UDP sender to %v: %v", detector.addr, err)
		return
	}
	defer func(conn *net.UDPConn) {
		err := conn.Close()
		if err != nil {
			log.Printf("Failed to close UDP sender: %v", err)
		}
	}(conn)

	jsonMsg, _ := json.Marshal(Message{detector.id})

	for {
		_, err := conn.Write(jsonMsg)
		if err != nil {
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
	defer func(listener *net.UDPConn) {
		err := listener.Close()
		if err != nil {
			log.Printf("Failed to close UDP multicast receiver: %v", err)
		}
	}(listener)

	buffer := make([]byte, bufferSize)

	for {
		n, senderAddr, err := listener.ReadFromUDP(buffer)
		if err != nil {
			continue
		}

		var msg Message
		if json.Unmarshal(buffer[:n], &msg) != nil {
			continue
		}

		if msg.ID == detector.id {
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
		// Канал заполнен, пропускаем обновление
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

	// Первоначальное отображение пустой таблицы
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
		lastSeen := detector.lastSeen[id]
		status := "Online"

		// Определяем статус на основе времени последнего сообщения
		timeSince := time.Since(lastSeen)
		if timeSince > nodeTimeout {
			status = "Offline"
		}

		nodes = append(nodes, NodeInfo{
			ID:       id,
			Address:  addr,
			LastSeen: lastSeen,
			Status:   status,
		})
	}
	detector.mu.RUnlock()

	// Сортируем по IP адресу для стабильного отображения
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Address.String() < nodes[j].Address.String()
	})

	// Перемещаем курсор в начало области таблицы
	detector.clearScreen()
	detector.initTable()

	// Заголовок таблицы
	fmt.Printf("%-10s %-20s %-25s %-10s %-15s\n",
		"№", "Node ID", "IP:Port", "Status", "Last Seen")
	fmt.Println(strings.Repeat("-", 85))

	// Отображаем узлы
	for i, node := range nodes {
		var addrStr string
		if node.Address.IP.To4() == nil {
			addrStr = fmt.Sprintf("[%s]:%d", node.Address.IP.String(), node.Address.Port)
		} else {
			addrStr = fmt.Sprintf("%s:%d", node.Address.IP.String(), node.Address.Port)
		}

		nodeID := node.ID.String()[:8] + "..."
		lastSeenStr := node.LastSeen.Format("15:04:05")

		statusSymbol := "..."
		switch node.Status {
		case "Online":
			statusSymbol = "🟢"
		}

		fmt.Printf("%-10d %-20s %-25s %-10s %-15s\n",
			i+1, nodeID, addrStr, statusSymbol+" "+node.Status, lastSeenStr)
	}

	// Добавляем строку итогов
	fmt.Println(strings.Repeat("-", 85))
	fmt.Printf("Total active nodes: %d", len(nodes))

	// Очищаем остальные строки от предыдущего вывода
	detector.clearRemainingLines()

	// Обновляем время последнего обновления в нижней части
	fmt.Printf("\n\nLast updated: %s", time.Now().Format("15:04:05"))
}

func (detector *Detector) clearScreen() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls")
	default:
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to clear screen: %v", err)
	}
}

func (detector *Detector) clearRemainingLines() {
	// Очищаем оставшуюся часть экрана от курсора до конца
	fmt.Print("\033[J")
}
