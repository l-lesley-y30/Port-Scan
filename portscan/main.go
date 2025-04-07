package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanResult holds the result of a single port scan
type ScanResult struct {
	Target string `json:"target"`
	Port   int    `json:"port"`
	Banner string `json:"banner,omitempty"` // Optional banner if available
}

// Command-line flags
var (
	targets     string // Comma-separated list of targets
	startPort   int    // Start of port range
	endPort     int    // End of port range
	workerCount int    // Number of concurrent workers
	timeout     int    // Timeout in seconds for each connection attempt
	jsonOutput  bool   // Output format flag
	portList    string // Optional list of specific ports
)

// Initialize command-line flags
func init() {
	flag.StringVar(&targets, "targets", "scanme.nmap.org", "Comma-separated list of IP addresses or hostnames")
	flag.IntVar(&startPort, "start-port", 1, "Starting port (default 1)")
	flag.IntVar(&endPort, "end-port", 1024, "Ending port (default 1024)")
	flag.IntVar(&workerCount, "workers", 100, "Number of concurrent workers")
	flag.IntVar(&timeout, "timeout", 5, "Connection timeout in seconds")
	flag.BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	flag.StringVar(&portList, "ports", "", "Comma-separated list of specific ports to scan (overrides start-end range)")
}

// Attempt to read a banner from an open connection
func bannerGrab(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) // Set read timeout
	reader := bufio.NewReader(conn)
	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)
	return string(buf[:n])
}

// Worker function that scans ports received from the task channel
func worker(wg *sync.WaitGroup, tasks chan string, results chan ScanResult, dialer net.Dialer, totalPorts int) {
	defer wg.Done()
	for task := range tasks {
		parts := strings.Split(task, ":")
		port, _ := strconv.Atoi(parts[1])
		fmt.Printf("Scanning port %d/%d on %s\n", port, totalPorts, parts[0])
		for i := 0; i < 3; i++ { // Retry up to 3 times with exponential backoff
			conn, err := dialer.Dial("tcp", task)
			if err == nil {
				banner := bannerGrab(conn)
				results <- ScanResult{Target: parts[0], Port: port, Banner: banner}
				conn.Close()
				break
			}
			time.Sleep(time.Duration(1<<i) * time.Second) // Exponential backoff
		}
	}
}

// Parse ports from either a range or a specific list
func parsePorts() []int {
	if portList != "" {
		ports := []int{}
		for _, p := range strings.Split(portList, ",") {
			if val, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				ports = append(ports, val)
			}
		}
		return ports
	}

	// Use the range if no specific list is provided
	ports := make([]int, 0, endPort-startPort+1)
	for p := startPort; p <= endPort; p++ {
		ports = append(ports, p)
	}
	return ports
}

func main() {
	flag.Parse() // Parse command-line arguments

	targetList := strings.Split(targets, ",")
	ports := parsePorts()
	totalTasks := len(targetList) * len(ports)

	var wg sync.WaitGroup
	taskChan := make(chan string, 1000)             // Queue of scan tasks
	resultChan := make(chan ScanResult, totalTasks) // Channel for storing successful scans

	dialer := net.Dialer{Timeout: time.Duration(timeout) * time.Second}

	startTime := time.Now() // Start timing the scan

	// Start worker goroutines
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(&wg, taskChan, resultChan, dialer, len(ports))
	}

	// Feed tasks into the task channel
	go func() {
		for _, target := range targetList {
			for _, port := range ports {
				taskChan <- net.JoinHostPort(strings.TrimSpace(target), strconv.Itoa(port))
			}
		}
		close(taskChan) // Close task channel after all jobs are sent
	}()

	wg.Wait()         // Wait for all workers to finish
	close(resultChan) // Close result channel after workers are done
	elapsed := time.Since(startTime)

	// Collect results from the result channel
	results := []ScanResult{}
	for r := range resultChan {
		results = append(results, r)
	}

	// Output results
	if jsonOutput {
		output, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(output))
	} else {
		for _, r := range results {
			fmt.Printf("[+] %s:%d OPEN", r.Target, r.Port)
			if r.Banner != "" {
				fmt.Printf(" - Banner: %q", r.Banner)
			}
			fmt.Println()
		}
		// Print scan summary
		fmt.Printf("\nScan Summary:\n")
		fmt.Printf("  Open Ports: %d\n", len(results))
		fmt.Printf("  Total Ports Scanned: %d\n", totalTasks)
		fmt.Printf("  Time Taken: %s\n", elapsed)
	}
}
