package detector

import (
	"encoding/json"
	"log"
	"net"
	"strconv"
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

type Detector struct {
	id       uuid.UUID                  // Уникальный идентификатор этой копии приложения
	addr     *net.UDPAddr               // Адрес мультикаст-группы, к которой мы подключаемся
	nodes    map[uuid.UUID]*net.UDPAddr // Словарь всех "живых" копий с их UUID и IP-адресами
	lastSeen map[uuid.UUID]time.Time    // Время последнего сообщения от каждой копии
	mu       sync.RWMutex               // Мьютекс для безопасного доступа к nodes и lastSeen из разных горутин
}

func Start(addr string, port int) {
	id, _ := uuid.NewUUID()

	// net.JoinHostPort соединяет IP и порт в правильную строку адреса, учитывая особенности IPv4 и IPv6:
	// получить структуру UDPAddr
	multicastAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		log.Printf("Failed to resolve UDP address: %v", err)
		return
	}

	// Проверяем, что это действительно мультикаст-адрес
	if !multicastAddr.IP.IsMulticast() {
		log.Printf("Provided address '%s' is not a valid multicast address", multicastAddr)
		return
	}

	// Создаем детектор
	detector := &Detector{
		id:       id,
		addr:     multicastAddr,
		nodes:    make(map[uuid.UUID]*net.UDPAddr),
		lastSeen: make(map[uuid.UUID]time.Time),
	}

	var waitGroup sync.WaitGroup
	waitGroup.Add(1)

	go detector.sender(&waitGroup)
	go detector.receiver(&waitGroup)
	go detector.cleaner(&waitGroup)

	waitGroup.Wait()
}

func (detector *Detector) sender(waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	// получаем объект для отправки/приёма UDP-пакетов
	conn, err := net.DialUDP("udp", nil, detector.addr)
	if err != nil {
		log.Printf("Failed to start UDP sender to %v: %v", detector.addr, err)
		return
	}
	defer conn.Close()

	jsonMsg, _ := json.Marshal(Message{detector.id})
	log.Printf("Sender started on %v", conn.LocalAddr())

	for {
		conn.Write(jsonMsg)
		time.Sleep(sendInterval)
	}
}

func (detector *Detector) receiver(waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	listener, err := net.ListenMulticastUDP("udp", nil, detector.addr)
	if err != nil {
		log.Printf("Failed to start UDP multicast receiver on %v: %v", detector.addr, err)
		return
	}
	defer listener.Close()

	log.Printf("Receiver listening on %v", detector.addr)
	buffer := make([]byte, bufferSize)

	for {
		n, senderAddr, err := listener.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading UDP message from %v: %v", senderAddr, err)
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
		for id, lastTime := range detector.lastSeen {
			if time.Since(lastTime) > nodeTimeout {
				addr := detector.nodes[id]
				delete(detector.nodes, id)
				delete(detector.lastSeen, id)
				log.Printf("Copy %v removed", addr)
			}
		}
		detector.mu.Unlock()
	}
}

func (detector *Detector) addOrUpdateNode(id uuid.UUID, addr *net.UDPAddr) {
	detector.mu.Lock()
	defer detector.mu.Unlock()

	_, exists := detector.nodes[id]
	detector.nodes[id] = addr
	detector.lastSeen[id] = time.Now()

	if exists {
		log.Printf("Copy %v updated", addr)
	} else {
		log.Printf("Copy %v added", addr)
	}
}
