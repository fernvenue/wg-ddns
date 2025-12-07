package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/fernvenue/wg-ddns/docs"
)

const Version = "1.2"

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

var logLevelNames = map[LogLevel]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
}

type Logger struct {
	level LogLevel
}

func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	timestamp := time.Now().Format("2006/01/02 15:04:05")
	levelName := logLevelNames[level]
	message := fmt.Sprintf(format, args...)
	fmt.Printf("%s [%s] %s\n", timestamp, levelName, message)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

var logger *Logger

func parseLogLevel(level string) LogLevel {
	switch strings.ToLower(level) {
	case "debug":
		return DEBUG
	case "info":
		return INFO
	case "warn", "warning":
		return WARN
	case "error":
		return ERROR
	default:
		return INFO
	}
}

type Config struct {
	Interface string
	Endpoint  string
	Hostname  string
	LastIPv4  net.IP
	LastIPv6  net.IP
}

type DDNSMonitor struct {
	configs         []Config
	conn            *dbus.Conn
	singleInterface string
	apiEnabled      bool
	listenAddress   string
	listenPort      string
	apiKey          string
	httpServer      *http.Server
	checkInterval   time.Duration
}

type RestartRequest struct {
	Interface string `json:"interface" binding:"required"`
}

type RestartResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type Args struct {
	singleInterface string
	listenAddress   string
	listenPort      string
	apiKey          string
	logLevel        string
	checkInterval   string
	help            bool
	version         bool
	checkOnly       bool
}

func parseArgs() *Args {
	args := &Args{}

	args.singleInterface = os.Getenv("WG_DDNS_SINGLE_INTERFACE")
	args.listenAddress = os.Getenv("WG_DDNS_LISTEN_ADDRESS")
	args.listenPort = os.Getenv("WG_DDNS_LISTEN_PORT")
	args.apiKey = os.Getenv("WG_DDNS_API_KEY")
	args.logLevel = os.Getenv("WG_DDNS_LOG_LEVEL")
	args.checkInterval = os.Getenv("WG_DDNS_CHECK_INTERVAL")

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]

		if !strings.HasPrefix(arg, "--") {
			if arg == "-h" || arg == "-help" {
				args.help = true
				continue
			}
			fmt.Fprintf(os.Stderr, "Error: Invalid argument format '%s'. Only double-dash (--) options are supported.\n", arg)
			os.Exit(1)
		}

		if arg == "--help" {
			args.help = true
			continue
		}

		if arg == "--version" {
			args.version = true
			continue
		}

		if arg == "--check-only" {
			args.checkOnly = true
			continue
		}

		parts := strings.SplitN(arg, "=", 2)
		var key, value string

		if len(parts) == 2 {
			key = parts[0]
			value = parts[1]
		} else {
			key = arg
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "--") {
				i++
				value = os.Args[i]
			}
		}

		switch key {
		case "--single-interface":
			args.singleInterface = value
		case "--listen-address":
			args.listenAddress = value
		case "--listen-port":
			args.listenPort = value
		case "--api-key":
			args.apiKey = value
		case "--log-level":
			args.logLevel = value
		case "--check-interval":
			args.checkInterval = value
		default:
			fmt.Fprintf(os.Stderr, "Error: Unknown option '%s'\n", key)
			os.Exit(1)
		}
	}

	return args
}

func printUsage() {
	fmt.Printf("Usage: %s [OPTIONS]\n\n", os.Args[0])
	fmt.Println("OPTIONS:")
	fmt.Println("  --single-interface string    Monitor only the specified WireGuard interface")
	fmt.Println("  --listen-address string      HTTP API listen address")
	fmt.Println("  --listen-port string         HTTP API listen port")
	fmt.Println("  --api-key string             API key for authentication")
	fmt.Println("  --log-level string           Log level: debug, info, warn, error (default: info)")
	fmt.Println("  --check-interval string      DNS check interval (e.g., 10s, 1m, 5m) (default: 10s)")
	fmt.Println("  --check-only                 Check active WireGuard interfaces and exit")
	fmt.Println("  --version                    Show version information")
	fmt.Println("  --help                       Show this help message")
	fmt.Println("")
	fmt.Println("ENVIRONMENT VARIABLES:")
	fmt.Println("  WG_DDNS_SINGLE_INTERFACE     Same as --single-interface")
	fmt.Println("  WG_DDNS_LISTEN_ADDRESS       Same as --listen-address")
	fmt.Println("  WG_DDNS_LISTEN_PORT          Same as --listen-port")
	fmt.Println("  WG_DDNS_API_KEY              Same as --api-key")
	fmt.Println("  WG_DDNS_LOG_LEVEL            Same as --log-level")
	fmt.Println("  WG_DDNS_CHECK_INTERVAL       Same as --check-interval")
	fmt.Println("")
	fmt.Println("NOTES:")
	fmt.Println("  - All three API options (--listen-address, --listen-port, --api-key) must be provided together to enable API functionality")
	fmt.Println("  - Command line options override environment variables")
	fmt.Println("  - Use double-dash (--) format for all options")
}

func printVersion() {
	fmt.Printf("wg-ddns version %s\n", Version)
}

func performCheckOnly(singleInterface string) {
	conn, err := dbus.NewWithContext(context.Background())
	if err != nil {
		fmt.Printf("Error: Failed to connect to systemd: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	var configs []Config
	
	if singleInterface != "" {
		configPath := filepath.Join("/etc/wireguard", singleInterface+".conf")
		if err := parseWireGuardConfigForCheck(singleInterface, configPath, &configs); err != nil {
			fmt.Printf("Error: Failed to parse config for %s: %v\n", singleInterface, err)
			os.Exit(1)
		}
		fmt.Printf("Checking single interface: %s\n", singleInterface)
	} else {
		if err := discoverWireGuardConfigsForCheck(conn, &configs); err != nil {
			fmt.Printf("Error: Failed to discover WireGuard interfaces: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Scanning all active WireGuard interfaces...\n")
	}

	if len(configs) == 0 {
		fmt.Println("No active WireGuard interfaces with domain endpoints found.")
		return
	}

	fmt.Printf("\nFound %d active WireGuard interface(s) with domain endpoints:\n\n", len(configs))
	
	for i, config := range configs {
		fmt.Printf("%d. Interface: %s\n", i+1, config.Interface)
		fmt.Printf("   Endpoint: %s\n", config.Endpoint)
		fmt.Printf("   Hostname: %s\n", config.Hostname)

		if config.LastIPv4 != nil {
			fmt.Printf("   IPv4: %s\n", config.LastIPv4)
		} else {
			fmt.Printf("   IPv4: (not resolved)\n")
		}

		if config.LastIPv6 != nil {
			fmt.Printf("   IPv6: %s\n", config.LastIPv6)
		} else {
			fmt.Printf("   IPv6: (not resolved)\n")
		}

		fmt.Println()
	}
}

func discoverWireGuardConfigsForCheck(conn *dbus.Conn, configs *[]Config) error {
	units, err := conn.ListUnitsContext(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list systemd units: %w", err)
	}

	for _, unit := range units {
		if strings.HasPrefix(unit.Name, "wg-quick@") && strings.HasSuffix(unit.Name, ".service") && unit.ActiveState == "active" {
			interfaceName := strings.TrimPrefix(unit.Name, "wg-quick@")
			interfaceName = strings.TrimSuffix(interfaceName, ".service")

			configPath := filepath.Join("/etc/wireguard", interfaceName+".conf")
			if err := parseWireGuardConfigForCheck(interfaceName, configPath, configs); err != nil {
				continue
			}
		}
	}

	return nil
}

func parseWireGuardConfigForCheck(interfaceName, configPath string, configs *[]Config) error {
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file %s: %w", configPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	endpointRegex := regexp.MustCompile(`^\s*Endpoint\s*=\s*(.+)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		matches := endpointRegex.FindStringSubmatch(line)
		if len(matches) == 2 {
			endpoint := strings.TrimSpace(matches[1])

			host, _, err := net.SplitHostPort(endpoint)
			if err != nil {
				continue
			}

			// Check if host is already an IP address (IPv4 or IPv6)
			if net.ParseIP(host) != nil {
				continue
			}

			// Host is a domain name, resolve both IPv4 and IPv6
			config := Config{
				Interface: interfaceName,
				Endpoint:  endpoint,
				Hostname:  host,
			}

			// Resolve IPv4 (A record)
			if ipv4, err := net.ResolveIPAddr("ip4", host); err == nil {
				config.LastIPv4 = ipv4.IP
			}

			// Resolve IPv6 (AAAA record)
			if ipv6, err := net.ResolveIPAddr("ip6", host); err == nil {
				config.LastIPv6 = ipv6.IP
			}

			*configs = append(*configs, config)
		}
	}

	return scanner.Err()
}

// @title WireGuard DDNS API
// @version 1.0
// @description API for WireGuard DDNS monitor
// @host localhost:8080
// @BasePath /api/v1
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-API-Key
func main() {
	args := parseArgs()

	if args.help {
		printUsage()
		os.Exit(0)
	}

	if args.version {
		printVersion()
		os.Exit(0)
	}

	if args.checkOnly {
		performCheckOnly(args.singleInterface)
		os.Exit(0)
	}

	logLevel := INFO
	if args.logLevel != "" {
		logLevel = parseLogLevel(args.logLevel)
	}

	logger = &Logger{level: logLevel}

	log.SetOutput(io.Discard)
	gin.DefaultWriter = io.Discard
	gin.DefaultErrorWriter = io.Discard

	checkInterval := 10 * time.Second
	if args.checkInterval != "" {
		var err error
		checkInterval, err = time.ParseDuration(args.checkInterval)
		if err != nil {
			logger.Error("Invalid check interval format: %v", err)
			os.Exit(1)
		}
		if checkInterval < time.Second {
			logger.Error("Check interval must be at least 1 second")
			os.Exit(1)
		}
	}

	apiEnabled := args.listenAddress != "" && args.listenPort != "" && args.apiKey != ""

	monitor := &DDNSMonitor{
		singleInterface: args.singleInterface,
		apiEnabled:      apiEnabled,
		listenAddress:   args.listenAddress,
		listenPort:      args.listenPort,
		apiKey:          args.apiKey,
		checkInterval:   checkInterval,
	}

	if err := monitor.initialize(); err != nil {
		logger.Error("Failed to initialize monitor: %v", err)
		os.Exit(1)
	}
	defer monitor.cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal")
		cancel()
	}()

	if monitor.apiEnabled {
		go monitor.startHTTPServer(ctx)
	}

	logger.Info("WireGuard DDNS monitor started")
	monitor.run(ctx)
}

func (m *DDNSMonitor) initialize() error {
	var err error
	m.conn, err = dbus.NewWithContext(context.Background())
	if err != nil {
		return fmt.Errorf("failed to connect to systemd: %w", err)
	}

	if m.singleInterface != "" {
		return m.parseSingleInterface()
	}
	return m.discoverWireGuardConfigs()
}

func (m *DDNSMonitor) parseSingleInterface() error {
	configPath := filepath.Join("/etc/wireguard", m.singleInterface+".conf")
	if err := m.parseWireGuardConfig(m.singleInterface, configPath); err != nil {
		return fmt.Errorf("failed to parse config for %s: %w", m.singleInterface, err)
	}

	logger.Info("Monitoring single interface: %s with %d domain endpoints", m.singleInterface, len(m.configs))
	return nil
}

func (m *DDNSMonitor) cleanup() {
	if m.httpServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.httpServer.Shutdown(shutdownCtx)
	}
	if m.conn != nil {
		m.conn.Close()
	}
}

func (m *DDNSMonitor) discoverWireGuardConfigs() error {
	units, err := m.conn.ListUnitsContext(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list systemd units: %w", err)
	}

	for _, unit := range units {
		if strings.HasPrefix(unit.Name, "wg-quick@") && strings.HasSuffix(unit.Name, ".service") && unit.ActiveState == "active" {
			interfaceName := strings.TrimPrefix(unit.Name, "wg-quick@")
			interfaceName = strings.TrimSuffix(interfaceName, ".service")

			configPath := filepath.Join("/etc/wireguard", interfaceName+".conf")
			if err := m.parseWireGuardConfig(interfaceName, configPath); err != nil {
				logger.Warn("Failed to parse config for %s: %v", interfaceName, err)
				continue
			}
		}
	}

	logger.Info("Discovered %d WireGuard interfaces with domain endpoints", len(m.configs))
	return nil
}

func (m *DDNSMonitor) parseWireGuardConfig(interfaceName, configPath string) error {
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file %s: %w", configPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	endpointRegex := regexp.MustCompile(`^\s*Endpoint\s*=\s*(.+)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		matches := endpointRegex.FindStringSubmatch(line)
		if len(matches) == 2 {
			endpoint := strings.TrimSpace(matches[1])

			host, _, err := net.SplitHostPort(endpoint)
			if err != nil {
				continue
			}

			// Check if host is already an IP address (IPv4 or IPv6)
			if net.ParseIP(host) != nil {
				continue
			}

			// Host is a domain name, resolve both IPv4 and IPv6
			config := Config{
				Interface: interfaceName,
				Endpoint:  endpoint,
				Hostname:  host,
			}

			// Resolve IPv4 (A record)
			if ipv4, err := net.ResolveIPAddr("ip4", host); err == nil {
				config.LastIPv4 = ipv4.IP
				logger.Debug("Found domain endpoint: %s -> %s (IPv4, interface: %s)", host, ipv4.IP, interfaceName)
			}

			// Resolve IPv6 (AAAA record)
			if ipv6, err := net.ResolveIPAddr("ip6", host); err == nil {
				config.LastIPv6 = ipv6.IP
				logger.Debug("Found domain endpoint: %s -> %s (IPv6, interface: %s)", host, ipv6.IP, interfaceName)
			}

			m.configs = append(m.configs, config)
		}
	}

	return scanner.Err()
}

func (m *DDNSMonitor) checkEndpoints() {
	for i := range m.configs {
		config := &m.configs[i]
		needsRestart := false

		logger.Debug("Resolving DNS for %s (interface: %s)", config.Hostname, config.Interface)

		// Check IPv4 (A record)
		currentIPv4, err := net.ResolveIPAddr("ip4", config.Hostname)
		if err != nil {
			logger.Debug("Failed to resolve IPv4 for %s: %v", config.Hostname, err)
		} else {
			logger.Debug("DNS resolution result for %s: %s (IPv4, interface: %s)", config.Hostname, currentIPv4.IP, config.Interface)

			// Check if IPv4 changed
			if !ipEqual(config.LastIPv4, currentIPv4.IP) {
				logger.Warn("IPv4 change detected for %s: %s -> %s (interface: %s)",
					config.Hostname, config.LastIPv4, currentIPv4.IP, config.Interface)
				config.LastIPv4 = currentIPv4.IP
				needsRestart = true
			}
		}

		// Check IPv6 (AAAA record)
		currentIPv6, err := net.ResolveIPAddr("ip6", config.Hostname)
		if err != nil {
			logger.Debug("Failed to resolve IPv6 for %s: %v", config.Hostname, err)
		} else {
			logger.Debug("DNS resolution result for %s: %s (IPv6, interface: %s)", config.Hostname, currentIPv6.IP, config.Interface)

			// Check if IPv6 changed
			if !ipEqual(config.LastIPv6, currentIPv6.IP) {
				logger.Warn("IPv6 change detected for %s: %s -> %s (interface: %s)",
					config.Hostname, config.LastIPv6, currentIPv6.IP, config.Interface)
				config.LastIPv6 = currentIPv6.IP
				needsRestart = true
			}
		}

		// Restart interface if any IP changed
		if needsRestart {
			if err := m.restartWireGuardService(config.Interface); err != nil {
				logger.Error("Failed to restart wg-quick@%s: %v", config.Interface, err)
			} else {
				logger.Warn("Successfully restarted wg-quick@%s.service", config.Interface)
			}
		}
	}
}

// ipEqual compares two IP addresses, handling nil values
func ipEqual(ip1, ip2 net.IP) bool {
	if ip1 == nil && ip2 == nil {
		return true
	}
	if ip1 == nil || ip2 == nil {
		return false
	}
	return ip1.Equal(ip2)
}

func (m *DDNSMonitor) restartWireGuardService(interfaceName string) error {
	serviceName := fmt.Sprintf("wg-quick@%s.service", interfaceName)

	reschan := make(chan string)
	_, err := m.conn.RestartUnitContext(context.Background(), serviceName, "replace", reschan)
	if err != nil {
		return fmt.Errorf("failed to restart service %s: %w", serviceName, err)
	}

	job := <-reschan
	if job != "done" {
		return fmt.Errorf("service restart job failed: %s", job)
	}

	return nil
}

func (m *DDNSMonitor) startHTTPServer(ctx context.Context) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(m.loggingMiddleware())

	v1 := router.Group("/api/v1")
	v1.Use(m.authMiddleware())
	{
		v1.POST("/restart", m.handleRestart)
		v1.GET("/interfaces", m.handleListInterfaces)
	}

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	addr := fmt.Sprintf("%s:%s", m.listenAddress, m.listenPort)
	m.httpServer = &http.Server{
		Addr:    addr,
		Handler: router,
	}

	logger.Info("HTTP API server started on %s", addr)
	logger.Info("Swagger UI available at http://%s/swagger/index.html", addr)

	go func() {
		if err := m.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error: %v", err)
		}
	}()

	<-ctx.Done()
}

func (m *DDNSMonitor) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		path := c.Request.URL.Path
		statusCode := c.Writer.Status()

		logger.Info("API %s %s - %d - %v - %s", method, path, statusCode, duration, clientIP)
	}
}

func (m *DDNSMonitor) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey != m.apiKey {
			logger.Warn("API authentication failed from %s", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// @Summary Restart WireGuard interface
// @Description Restart a specific WireGuard interface
// @Tags interfaces
// @Accept json
// @Produce json
// @Param X-API-Key header string true "API Key"
// @Param request body RestartRequest true "Interface to restart"
// @Success 200 {object} RestartResponse
// @Failure 400 {object} RestartResponse
// @Failure 401 {object} RestartResponse
// @Failure 404 {object} RestartResponse
// @Failure 500 {object} RestartResponse
// @Router /restart [post]
func (m *DDNSMonitor) handleRestart(c *gin.Context) {
	var req RestartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Debug("API restart request - invalid JSON from %s", c.ClientIP())
		c.JSON(http.StatusBadRequest, RestartResponse{
			Success: false,
			Message: "Invalid request format",
		})
		return
	}

	logger.Info("API restart request for interface '%s' from %s", req.Interface, c.ClientIP())

	if m.singleInterface != "" && req.Interface != m.singleInterface {
		logger.Warn("API restart request denied - interface '%s' not allowed (single-interface mode: %s)", req.Interface, m.singleInterface)
		c.JSON(http.StatusBadRequest, RestartResponse{
			Success: false,
			Message: fmt.Sprintf("Only interface '%s' is monitored", m.singleInterface),
		})
		return
	}

	found := false
	for _, config := range m.configs {
		if config.Interface == req.Interface {
			found = true
			break
		}
	}

	if !found {
		logger.Warn("API restart request denied - interface '%s' not found in monitored interfaces", req.Interface)
		c.JSON(http.StatusNotFound, RestartResponse{
			Success: false,
			Message: fmt.Sprintf("Interface '%s' not found in monitored interfaces", req.Interface),
		})
		return
	}

	if err := m.restartWireGuardService(req.Interface); err != nil {
		logger.Error("API restart request failed for interface '%s': %v", req.Interface, err)
		c.JSON(http.StatusInternalServerError, RestartResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to restart interface: %v", err),
		})
		return
	}

	logger.Info("API restart request completed successfully for interface '%s'", req.Interface)
	c.JSON(http.StatusOK, RestartResponse{
		Success: true,
		Message: fmt.Sprintf("Interface '%s' restarted successfully", req.Interface),
	})
}

// @Summary List monitored interfaces
// @Description Get list of all monitored WireGuard interfaces
// @Tags interfaces
// @Produce json
// @Param X-API-Key header string true "API Key"
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /interfaces [get]
func (m *DDNSMonitor) handleListInterfaces(c *gin.Context) {
	logger.Debug("API interfaces request from %s", c.ClientIP())

	interfaces := make([]map[string]interface{}, 0, len(m.configs))
	for _, config := range m.configs {
		interfaceInfo := map[string]interface{}{
			"interface": config.Interface,
			"endpoint":  config.Endpoint,
			"hostname":  config.Hostname,
		}

		if config.LastIPv4 != nil {
			interfaceInfo["ipv4"] = config.LastIPv4.String()
		} else {
			interfaceInfo["ipv4"] = nil
		}

		if config.LastIPv6 != nil {
			interfaceInfo["ipv6"] = config.LastIPv6.String()
		} else {
			interfaceInfo["ipv6"] = nil
		}

		interfaces = append(interfaces, interfaceInfo)
	}

	response := map[string]interface{}{
		"single_interface_mode": m.singleInterface != "",
		"monitored_interface":   m.singleInterface,
		"interfaces":            interfaces,
		"total_count":           len(interfaces),
	}

	c.JSON(http.StatusOK, response)
}

func (m *DDNSMonitor) run(ctx context.Context) {
	logger.Info("DNS check interval: %v", m.checkInterval)
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Shutting down monitor")
			return
		case <-ticker.C:
			logger.Debug("Starting scheduled endpoint check")
			m.checkEndpoints()
			logger.Debug("Completed scheduled endpoint check")
		}
	}
}
