// Package main is the entry point for the 3x-ui web panel application.
// It initializes the database, web server, and handles command-line operations for managing the panel.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"
	_ "unsafe"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/sub"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
	"github.com/mhsanaei/3x-ui/v2/web"
	"github.com/mhsanaei/3x-ui/v2/web/global"
	"github.com/mhsanaei/3x-ui/v2/web/service"

	"github.com/joho/godotenv"
	"github.com/op/go-logging"
)

// runWebServer initializes and starts the web server for the 3x-ui panel.
func runWebServer() {
	log.Printf("Starting %v %v", config.GetName(), config.GetVersion())

	switch config.GetLogLevel() {
	case config.Debug:
		logger.InitLogger(logging.DEBUG)
	case config.Info:
		logger.InitLogger(logging.INFO)
	case config.Notice:
		logger.InitLogger(logging.NOTICE)
	case config.Warning:
		logger.InitLogger(logging.WARNING)
	case config.Error:
		logger.InitLogger(logging.ERROR)
	default:
		log.Fatalf("Unknown log level: %v", config.GetLogLevel())
	}

	godotenv.Load()
	keepFilesPrivate()

	err := database.InitDB(config.GetDBPath())
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}

	var server *web.Server
	server = web.NewServer()
	global.SetWebServer(server)
	err = server.Start()
	if err != nil {
		log.Fatalf("Error starting web server: %v", err)
		return
	}

	var subServer *sub.Server
	subServer = sub.NewServer()
	global.SetSubServer(subServer)
	err = subServer.Start()
	if err != nil {
		log.Fatalf("Error starting sub server: %v", err)
		return
	}

	sigCh := make(chan os.Signal, 1)
	// Trap shutdown signals
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, sys.SIGUSR1)
	for {
		sig := <-sigCh

		switch sig {
		case syscall.SIGHUP:
			logger.Info("Received SIGHUP signal. Restarting servers...")

			// --- FIX FOR TELEGRAM BOT CONFLICT (409): Stop bot before restart ---
			service.StopBot()
			// --

			err := server.Stop()
			if err != nil {
				logger.Debug("Error stopping web server:", err)
			}
			err = subServer.Stop()
			if err != nil {
				logger.Debug("Error stopping sub server:", err)
			}

			server = web.NewServer()
			global.SetWebServer(server)
			err = server.Start()
			if err != nil {
				log.Fatalf("Error restarting web server: %v", err)
				return
			}
			log.Println("Web server restarted successfully.")

			subServer = sub.NewServer()
			global.SetSubServer(subServer)
			err = subServer.Start()
			if err != nil {
				log.Fatalf("Error restarting sub server: %v", err)
				return
			}
			log.Println("Sub server restarted successfully.")
		case sys.SIGUSR1:
			logger.Info("Received USR1 signal, restarting xray-core...")
			err := server.RestartXray()
			if err != nil {
				logger.Error("Failed to restart xray-core:", err)
			}

		default:
			// --- FIX FOR TELEGRAM BOT CONFLICT (409) on full shutdown ---
			service.StopBot()
			// ------------------------------------------------------------

			server.Stop()
			subServer.Stop()
			log.Println("Shutting down servers.")
			return
		}
	}
}

// errReported is returned by a command that has already printed why it
// failed: main only has to exit with an error status.
var errReported = errors.New("failed")

// resetSetting resets all panel settings to their default values.
func resetSetting() error {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println("Failed to initialize database:", err)
		return errReported
	}

	settingService := service.SettingService{}
	err = settingService.ResetSettings()
	if err != nil {
		fmt.Println("Failed to reset settings:", err)
		return errReported
	}
	fmt.Println("Settings successfully reset.")
	return nil
}

// showSetting displays the current panel settings if show is true.
func showSetting(show bool) {
	if show {
		settingService := service.SettingService{}
		port, err := settingService.GetPort()
		if err != nil {
			fmt.Println("get current port failed, error info:", err)
		}

		webBasePath, err := settingService.GetBasePath()
		if err != nil {
			fmt.Println("get webBasePath failed, error info:", err)
		}

		certFile, err := settingService.GetCertFile()
		if err != nil {
			fmt.Println("get cert file failed, error info:", err)
		}
		keyFile, err := settingService.GetKeyFile()
		if err != nil {
			fmt.Println("get key file failed, error info:", err)
		}

		userService := service.UserService{}
		userModel, err := userService.GetFirstUser()
		if err != nil {
			fmt.Println("get current user info failed, error info:", err)
		}

		if userModel.Username == "" || userModel.Password == "" {
			fmt.Println("current username or password is empty")
		}

		fmt.Println("current panel settings as follows:")
		if certFile == "" || keyFile == "" {
			fmt.Println("Warning: Panel is not secure with SSL")
		} else {
			fmt.Println("Panel is secure with SSL")
		}

		hasDefaultCredential := func() bool {
			return userModel.Username == "admin" && crypto.CheckPasswordHash(userModel.Password, "admin")
		}()

		fmt.Println("hasDefaultCredential:", hasDefaultCredential)
		fmt.Println("port:", port)
		fmt.Println("webBasePath:", webBasePath)
	}
}

// updateTgbotEnableSts enables or disables the Telegram bot notifications based on the status parameter.
func updateTgbotEnableSts(status bool) error {
	settingService := service.SettingService{}
	currentTgSts, err := settingService.GetTgbotEnabled()
	if err != nil {
		fmt.Println(err)
		return errReported
	}
	logger.Infof("current enabletgbot status[%v],need update to status[%v]", currentTgSts, status)
	if currentTgSts != status {
		err := settingService.SetTgbotEnabled(status)
		if err != nil {
			fmt.Println(err)
			return errReported
		} else {
			logger.Infof("SetTgbotEnabled[%v] success", status)
		}
	}
	return nil
}

// updateTgbotSetting updates Telegram bot settings including token, chat ID, and runtime schedule.
// updateXrayEgress sets instances' outgoing IPs from "name=ip,name=ip". An
// empty ip sends that instance from the server's default address again. A
// running panel applies it when it restarts.
func updateXrayEgress(spec string) error {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println("Error initializing database:", err)
		return errReported
	}
	settingService := service.SettingService{}
	m, err := settingService.GetInstanceEgress()
	if err != nil {
		fmt.Println("Error reading the outgoing IPs:", err)
		return errReported
	}
	names, err := service.XrayInstanceNames()
	if err != nil {
		fmt.Println("Error reading the inbounds:", err)
		return errReported
	}
	for _, part := range strings.Split(spec, ",") {
		name, ip, ok := strings.Cut(strings.TrimSpace(part), "=")
		name, ip = strings.TrimSpace(name), strings.TrimSpace(ip)
		if !ok || name == "" {
			fmt.Printf("Expected name=ip, got %q\n", part)
			return errReported
		}
		if !names[name] {
			fmt.Printf("Warning: no inbound runs in %s yet\n", name)
		}
		if ip == "" {
			delete(m, name)
			continue
		}
		norm, err := service.CheckEgressIP(ip)
		if err != nil {
			fmt.Printf("%s: %v\n", name, err)
			return errReported
		}
		m[name] = norm
	}
	if err := settingService.SetInstanceEgress(m); err != nil {
		fmt.Println("Error saving the outgoing IPs:", err)
		return errReported
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s -> %s\n", k, m[k])
	}
	fmt.Println("Saved. Restart the panel (x-ui restart) to apply.")
	return nil
}

func updateTgbotSetting(tgBotToken string, tgBotChatid string, tgBotRuntime string) error {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println("Error initializing database:", err)
		return errReported
	}

	settingService := service.SettingService{}

	if tgBotToken != "" {
		err := settingService.SetTgBotToken(tgBotToken)
		if err != nil {
			fmt.Printf("Error setting Telegram bot token: %v\n", err)
			return errReported
		}
		logger.Info("Successfully updated Telegram bot token.")
	}

	if tgBotRuntime != "" {
		err := settingService.SetTgbotRuntime(tgBotRuntime)
		if err != nil {
			fmt.Printf("Error setting Telegram bot runtime: %v\n", err)
			return errReported
		}
		logger.Infof("Successfully updated Telegram bot runtime to [%s].", tgBotRuntime)
	}

	if tgBotChatid != "" {
		err := settingService.SetTgBotChatId(tgBotChatid)
		if err != nil {
			fmt.Printf("Error setting Telegram bot chat ID: %v\n", err)
			return errReported
		}
		logger.Info("Successfully updated Telegram bot chat ID.")
	}
	return nil
}

// updateSetting updates various panel settings including port, credentials, base path, listen IP, and two-factor authentication.
func updateSetting(port int, username string, password string, webBasePath string, listenIP string, resetTwoFactor bool) error {
	failed := false
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println("Database initialization failed:", err)
		return errReported
	}

	settingService := service.SettingService{}
	userService := service.UserService{}

	if port > 0 {
		err := settingService.SetPort(port)
		if err != nil {
			fmt.Println("Failed to set port:", err)
			failed = true
		} else {
			fmt.Printf("Port set successfully: %v\n", port)
		}
	}

	if username != "" || password != "" {
		err := userService.UpdateFirstUser(username, password)
		if err != nil {
			fmt.Println("Failed to update username and password:", err)
			failed = true
		} else {
			fmt.Println("Username and password updated successfully")
		}
	}

	if webBasePath != "" {
		err := settingService.SetBasePath(webBasePath)
		if err != nil {
			fmt.Println("Failed to set base URI path:", err)
			failed = true
		} else {
			fmt.Println("Base URI path set successfully")
		}
	}

	if resetTwoFactor {
		err := settingService.SetTwoFactorEnable(false)

		if err != nil {
			fmt.Println("Failed to reset two-factor authentication:", err)
			failed = true
		} else {
			settingService.SetTwoFactorToken("")
			fmt.Println("Two-factor authentication reset successfully")
		}
	}

	if listenIP != "" {
		err := settingService.SetListen(listenIP)
		if err != nil {
			fmt.Println("Failed to set listen IP:", err)
			failed = true
		} else {
			fmt.Printf("listen %v set successfully", listenIP)
		}
	}
	if failed {
		return errReported
	}
	return nil
}

// updateCert updates the SSL certificate files for the panel.
func updateCert(publicKey string, privateKey string) error {
	failed := false
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return errReported
	}

	if (privateKey != "" && publicKey != "") || (privateKey == "" && publicKey == "") {
		settingService := service.SettingService{}
		err = settingService.SetCertFile(publicKey)
		if err != nil {
			fmt.Println("set certificate public key failed:", err)
			failed = true
		} else {
			fmt.Println("set certificate public key success")
		}

		err = settingService.SetKeyFile(privateKey)
		if err != nil {
			fmt.Println("set certificate private key failed:", err)
			failed = true
		} else {
			fmt.Println("set certificate private key success")
		}

		err = settingService.SetSubCertFile(publicKey)
		if err != nil {
			fmt.Println("set certificate for subscription public key failed:", err)
			failed = true
		} else {
			fmt.Println("set certificate for subscription public key success")
		}

		err = settingService.SetSubKeyFile(privateKey)
		if err != nil {
			fmt.Println("set certificate for subscription private key failed:", err)
			failed = true
		} else {
			fmt.Println("set certificate for subscription private key success")
		}
	} else {
		fmt.Println("both public and private key should be entered.")
		failed = true
	}
	if failed {
		return errReported
	}
	return nil
}

// GetCertificate displays the current SSL certificate settings if getCert is true.
func GetCertificate(getCert bool) {
	if getCert {
		settingService := service.SettingService{}
		certFile, err := settingService.GetCertFile()
		if err != nil {
			fmt.Println("get cert file failed, error info:", err)
		}
		keyFile, err := settingService.GetKeyFile()
		if err != nil {
			fmt.Println("get key file failed, error info:", err)
		}

		fmt.Println("cert:", certFile)
		fmt.Println("key:", keyFile)
	}
}

// GetListenIP displays the current panel listen IP address if getListen is true.
func GetListenIP(getListen bool) {
	if getListen {

		settingService := service.SettingService{}
		ListenIP, err := settingService.GetListen()
		if err != nil {
			log.Printf("Failed to retrieve listen IP: %v", err)
			return
		}

		fmt.Println("listenIP:", ListenIP)
	}
}

// migrateDb performs database migration operations for the 3x-ui panel.
func migrateDb() {
	inboundService := service.InboundService{}

	err := database.InitDB(config.GetDBPath())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Start migrating database...")
	inboundService.MigrateDB()
	fmt.Println("Migration done!")
}

// importDbFromURL replaces the panel database with one downloaded from url.
//
// The panel must not be running (the x-ui script stops it first and starts it
// again after). SQLite finds a database's rollback journal by its path while
// its locks belong to the open file, so a panel still holding the old file
// and this import, each on its own file under the same name, could play one
// another's journal into the wrong database. So it refuses while another
// process has the database open or a journal lies next to it.
//
// The download is checked, opened and migrated under a temporary name and
// put in place only when all of that worked, so a truncated download, a file
// that is not a panel database or a failed migration leaves the panel's
// database exactly as it was. The previous one is kept next to it, named
// after the time of the import.
func importDbFromURL(rawURL string) error {
	dbPath := config.GetDBPath()
	tempPath := dbPath + ".temp"
	if err := checkDBNotInUse(dbPath); err != nil {
		return err
	}

	fmt.Printf("Downloading database from %s\n", rawURL)

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(rawURL)
	if err != nil {
		return fmt.Errorf("failed to download database: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download database: server answered %s", resp.Status)
	}

	if err := os.MkdirAll(path.Dir(dbPath), fs.ModePerm); err != nil {
		return fmt.Errorf("failed to create database folder: %v", err)
	}
	discard := func() {
		os.Remove(tempPath)
		os.Remove(tempPath + "-journal")
	}
	discard()
	tempFile, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %v", err)
	}
	written, err := io.Copy(tempFile, resp.Body)
	tempFile.Close()
	if err != nil {
		discard()
		return fmt.Errorf("failed to save download: %v", err)
	}

	// Check it is a panel database before touching the live one. A captive
	// portal or a 404 page saved under the right name, or the database of
	// some other program, would otherwise take the panel down -- or bring
	// it back empty with the default login.
	check, err := os.Open(tempPath)
	if err != nil {
		discard()
		return fmt.Errorf("failed to reopen download: %v", err)
	}
	isDB, err := database.IsSQLiteDB(check)
	check.Close()
	if err != nil || !isDB {
		discard()
		return fmt.Errorf("downloaded file is not an SQLite database (%d bytes)", written)
	}
	if err := database.ValidateSQLiteDB(tempPath); err != nil {
		discard()
		return fmt.Errorf("downloaded database failed its integrity check: %v", err)
	}
	if err := database.ValidatePanelDB(tempPath); err != nil {
		discard()
		return fmt.Errorf("downloaded database cannot be used: %v", err)
	}

	// Opening it runs the schema migrations, so a database exported from an
	// older panel is brought up to date here rather than failing at boot.
	if err := database.InitDB(tempPath); err != nil {
		database.CloseDB()
		discard()
		return fmt.Errorf("failed to open the new database, kept the old one: %v", err)
	}
	inboundService := service.InboundService{}
	inboundService.MigrateDB()
	database.CloseDB()
	if err := database.ValidateSQLiteDB(tempPath); err != nil {
		discard()
		return fmt.Errorf("the new database failed its integrity check after migrating, kept the old one: %v", err)
	}

	// The panel may have been started meanwhile.
	if err := checkDBNotInUse(dbPath); err != nil {
		discard()
		return err
	}
	backupPath := ""
	if _, err := os.Stat(dbPath); err == nil {
		backupPath = dbPath + ".backup-" + time.Now().Format("20060102-150405")
		if err := os.Rename(dbPath, backupPath); err != nil {
			discard()
			return fmt.Errorf("failed to set aside the current database: %v", err)
		}
	}
	if err := os.Rename(tempPath, dbPath); err != nil {
		if backupPath != "" {
			os.Rename(backupPath, dbPath)
		}
		discard()
		return fmt.Errorf("failed to install the new database: %v", err)
	}

	fmt.Printf("Database replaced from %s (%d bytes).\n", rawURL, written)
	if backupPath != "" {
		fmt.Println("The previous database is kept as", backupPath)
	}
	return nil
}

// checkDBNotInUse fails while the database at dbPath may be in use: another
// process -- the panel -- has it open, or the journal of a write lies next
// to it.
func checkDBNotInUse(dbPath string) error {
	if pid := sys.OpenedBy(dbPath); pid > 0 {
		return fmt.Errorf("process %d has %s open: stop the panel first (x-ui stop)", pid, dbPath)
	}
	for _, suffix := range []string{"-journal", "-wal"} {
		if _, err := os.Stat(dbPath + suffix); err == nil {
			return fmt.Errorf("%s%s exists: the panel is running, or stopped in the middle of a write (start and stop it once to finish it)", dbPath, suffix)
		}
	}
	return nil
}

// main is the entry point of the 3x-ui application.
// It parses command-line arguments to run the web server, migrate database, or update settings.
func main() {
	if len(os.Args) < 2 {
		runWebServer()
		return
	}

	var showVersion bool
	flag.BoolVar(&showVersion, "v", false, "show version")

	runCmd := flag.NewFlagSet("run", flag.ExitOnError)

	settingCmd := flag.NewFlagSet("setting", flag.ExitOnError)
	var port int
	var username string
	var password string
	var webBasePath string
	var listenIP string
	var getListen bool
	var webCertFile string
	var webKeyFile string
	var tgbottoken string
	var tgbotchatid string
	var enabletgbot bool
	var tgbotRuntime string
	var reset bool
	var show bool
	var getCert bool
	var resetTwoFactor bool
	var xrayEgress string
	settingCmd.BoolVar(&reset, "reset", false, "Reset all settings")
	settingCmd.BoolVar(&show, "show", false, "Display current settings")
	settingCmd.IntVar(&port, "port", 0, "Set panel port number")
	settingCmd.StringVar(&username, "username", "", "Set login username")
	settingCmd.StringVar(&password, "password", "", "Set login password")
	settingCmd.StringVar(&webBasePath, "webBasePath", "", "Set base path for Panel")
	settingCmd.StringVar(&listenIP, "listenIP", "", "set panel listenIP IP")
	settingCmd.BoolVar(&resetTwoFactor, "resetTwoFactor", false, "Reset two-factor authentication settings")
	settingCmd.BoolVar(&getListen, "getListen", false, "Display current panel listenIP IP")
	settingCmd.BoolVar(&getCert, "getCert", false, "Display current certificate settings")
	settingCmd.StringVar(&webCertFile, "webCert", "", "Set path to public key file for panel")
	settingCmd.StringVar(&webKeyFile, "webCertKey", "", "Set path to private key file for panel")
	settingCmd.StringVar(&tgbottoken, "tgbottoken", "", "Set token for Telegram bot")
	settingCmd.StringVar(&tgbotRuntime, "tgbotRuntime", "", "Set cron time for Telegram bot notifications")
	settingCmd.StringVar(&tgbotchatid, "tgbotchatid", "", "Set chat ID for Telegram bot notifications")
	settingCmd.BoolVar(&enabletgbot, "enabletgbot", false, "Enable notifications via Telegram bot")
	settingCmd.StringVar(&xrayEgress, "xrayEgress", "", `Set xray instances' outgoing IPs: "xray-1=IP,xray-2=IP" (an empty IP clears it); applied at the next panel restart`)

	oldUsage := flag.Usage
	flag.Usage = func() {
		oldUsage()
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("    run            run web panel")
		fmt.Println("    migrate        migrate form other/old x-ui")
		fmt.Println("    setting        set settings")
		fmt.Println(`    db="<url>"     replace the database with one downloaded from <url>`)
	}

	flag.Parse()
	if showVersion {
		fmt.Println(config.GetVersion())
		return
	}

	if strings.HasPrefix(os.Args[1], "db=") {
		if err := importDbFromURL(strings.TrimPrefix(os.Args[1], "db=")); err != nil {
			fmt.Println("Database import failed:", err)
			os.Exit(1)
		}
		return
	}

	switch os.Args[1] {
	case "run":
		err := runCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		runWebServer()
	case "migrate":
		migrateDb()
	case "db":
		// Accepted as "x-ui db=<url>" (the script passes the whole word
		// through) and as "x-ui db <url>".
		var dbURL string
		if len(os.Args) > 2 {
			dbURL = os.Args[2]
		}
		dbURL = strings.TrimPrefix(dbURL, "url=")
		if dbURL == "" {
			fmt.Println(`Usage: x-ui db="https://example.com/x-ui.db"`)
			os.Exit(1)
		}
		if err := importDbFromURL(dbURL); err != nil {
			fmt.Println("Database import failed:", err)
			os.Exit(1)
		}
	case "setting":
		err := settingCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		// Every step runs, and the command fails if any of them did, so a
		// script calling it can tell.
		var errs []error
		if reset {
			errs = append(errs, resetSetting())
		} else {
			errs = append(errs, updateSetting(port, username, password, webBasePath, listenIP, resetTwoFactor))
		}
		if show {
			showSetting(show)
		}
		if getListen {
			GetListenIP(getListen)
		}
		if getCert {
			GetCertificate(getCert)
		}
		if (tgbottoken != "") || (tgbotchatid != "") || (tgbotRuntime != "") {
			errs = append(errs, updateTgbotSetting(tgbottoken, tgbotchatid, tgbotRuntime))
		}
		if enabletgbot {
			errs = append(errs, updateTgbotEnableSts(enabletgbot))
		}
		if xrayEgress != "" {
			errs = append(errs, updateXrayEgress(xrayEgress))
		}
		if errors.Join(errs...) != nil {
			os.Exit(1)
		}
	case "cert":
		err := settingCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if reset {
			err = updateCert("", "")
		} else {
			err = updateCert(webCertFile, webKeyFile)
		}
		if err != nil {
			os.Exit(1)
		}
	default:
		fmt.Println("Invalid subcommands")
		fmt.Println()
		runCmd.Usage()
		fmt.Println()
		settingCmd.Usage()
		os.Exit(1)
	}
}
