package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"litegix-agent/auth"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Config struct {
	ServerID    string
	ServerKey   string
	Environment string
	WebServer   string
}

// ProfileHandler struct
type ProfileHandler struct {
	rd     auth.AuthInterface
	tk     auth.TokenInterface
	config Config
}

func NewHandler(rd auth.AuthInterface, tk auth.TokenInterface, config Config) *ProfileHandler {
	return &ProfileHandler{rd, tk, config}
}

func (h *ProfileHandler) Login(c *gin.Context) {
	var u User
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}
	//compare the user from the request, with the one we defined:
	if u.Username != h.config.ServerID || u.Password != h.config.ServerKey {
		c.JSON(http.StatusUnauthorized, "Please provide valid login details")
		return
	}
	ts, err := h.tk.CreateToken(u.Username)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	saveErr := h.rd.CreateAuth(u.Username, ts)
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
		return
	}
	tokens := map[string]string{
		"access_token":  ts.AccessToken,
		"refresh_token": ts.RefreshToken,
	}
	c.JSON(http.StatusOK, tokens)
}

func (h *ProfileHandler) Logout(c *gin.Context) {
	//If metadata is passed and the tokens valid, delete them from the redis store
	metadata, _ := h.tk.ExtractTokenMetadata(c.Request)
	if metadata != nil {
		deleteErr := h.rd.DeleteTokens(metadata)
		if deleteErr != nil {
			c.JSON(http.StatusBadRequest, deleteErr.Error())
			return
		}
	}
	c.JSON(http.StatusOK, "Successfully logged out")
}

func (h *ProfileHandler) Refresh(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	refreshToken := mapToken["refresh_token"]

	//verify the token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})
	//if there is an error, the token must have expired
	if err != nil {
		c.JSON(http.StatusUnauthorized, "Refresh token expired")
		return
	}
	//is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		c.JSON(http.StatusUnauthorized, err)
		return
	}
	//Since token is valid, get the uuid:
	claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims
	if ok && token.Valid {
		refreshUuid, ok := claims["refresh_uuid"].(string) //convert the interface to string
		if !ok {
			c.JSON(http.StatusUnprocessableEntity, err)
			return
		}
		userId, roleOk := claims["user_id"].(string)
		if !roleOk {
			c.JSON(http.StatusUnprocessableEntity, "unauthorized")
			return
		}
		//Delete the previous Refresh Token
		delErr := h.rd.DeleteRefresh(refreshUuid)
		if delErr != nil { //if any goes wrong
			c.JSON(http.StatusUnauthorized, "unauthorized")
			return
		}
		//Create new pairs of refresh and access tokens
		ts, createErr := h.tk.CreateToken(userId)
		if createErr != nil {
			c.JSON(http.StatusForbidden, createErr.Error())
			return
		}
		//save the tokens metadata to redis
		saveErr := h.rd.CreateAuth(userId, ts)
		if saveErr != nil {
			c.JSON(http.StatusForbidden, saveErr.Error())
			return
		}
		tokens := map[string]string{
			"access_token":  ts.AccessToken,
			"refresh_token": ts.RefreshToken,
		}
		c.JSON(http.StatusCreated, tokens)
	} else {
		c.JSON(http.StatusUnauthorized, "refresh expired")
	}
}

/*func AddLinuxUser1(username, password string) {
	//Create a new user here and create a new home directory
	useradd := exec.Command("sh", "-c", "useradd -m "+username)
	err := useradd.Start()
	if err != nil {
		fmt.Println(err.Error())
	}

	useradd.Wait()
	//The following two are the ends of the pipe
	//Linux can use echo "password" | passwd --stdin username
	//Change the password directly
	ps := exec.Command("echo", password)
	grep := exec.Command("passwd", "--stdin", username)

	r, w := io.Pipe() // Create a pipeline
	defer r.Close()
	defer w.Close()
	ps.Stdout = w  // ps writes to one end of the pipe
	grep.Stdin = r // grep reads from one end of the pipe

	var buffer bytes.Buffer
	grep.Stdout = &buffer // The output of grep is buffer

	_ = ps.Start()
	_ = grep.Start()
	ps.Wait()
	w.Close()
	grep.Wait()
	io.Copy(os.Stdout, &buffer) // buffer copy to system standard output
}

func AddLinuxUser(username, password string) {
	//Create a new user here and create a new home directory
	useradd := exec.Command("sh", "-c", "useradd -m "+username+" -p "+password)
	err := useradd.Start()
	if err != nil {
		fmt.Println(err.Error())
	}

	useradd.Wait()
}*/

func ExecuteCommand(command string) bool {
	cmd := exec.Command("sh", "-c", command)

	if err := cmd.Start(); err != nil {
		log.Printf("Error starting command: %s......", err.Error())
		return false
	}
	if err := cmd.Wait(); err != nil {
		log.Printf("Error waiting for command execution: %s......", err.Error())
		return false
	}

	return true
}

type AsyncResult struct {
	errcode int
	result  string
}

func ExecuteCommandAsync(command string) <-chan AsyncResult {
	log.Println(command)
	result := make(chan AsyncResult)
	go func() {
		defer close(result)

		res := AsyncResult{}
		cmd := exec.Command("sh", "-c", command)
		stdout, err := cmd.CombinedOutput()
		if err != nil {
			res.errcode = -1
			log.Printf("Command execution exit code: %s", err.Error())
			if exitError, ok := err.(*exec.ExitError); ok {
				res.errcode = exitError.ExitCode()
				result <- res
			}
		} else {
			res.errcode = 0
			res.result = strings.TrimSpace(string(stdout))
		}
		result <- res
	}()
	return result
}

func ExecuteMySQLQueryAsync(query string) <-chan AsyncResult {
	// mysql -uroot -p${rootpasswd} -e
	command := fmt.Sprintf("mysql -uroot -e \"%s\"", query)
	return ExecuteCommandAsync(command)
}

func ExecuteMySQLQuery(query string) bool {
	// mysql -uroot -p${rootpasswd} -e
	command := fmt.Sprintf("mysql -uroot -e \"%s\"", query)
	log.Println(command)
	return ExecuteCommand(command)

	/*mysqlConf := struct {
		Client struct {
			User     string
			Password string
		}
	}{}

	err := gcfg.ReadFileInto(&mysqlConf, "/etc/mysql/conf.d/root.cnf")
	if err != nil {
		log.Fatalf("Failed to parse gcfg data: %s", err)
	}
	// toml.DecodeFile("/etc/mysql/conf.d/root.cnf", mysqlConf)
	var rootPassword = mysqlConf.Client.Password

	// mysql -uroot -p${rootpasswd} -e
	command := fmt.Sprintf("mysql -uroot -p%s -e \"%s\"", rootPassword, query)
	log.Println(command)
	return ExecuteCommand(command)*/
}

func (h *ProfileHandler) CreateSystemUser(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	username := mapToken["name"]
	password := mapToken["password"]
	log.Println(fmt.Sprintf("Create system user, username: %s, password: %s", username, password))

	command := fmt.Sprintf("useradd -m \"%s\" --password \"%s\"", username, password)
	res := <-ExecuteCommandAsync(command)
	c.JSON(http.StatusCreated, gin.H{
		"error": res.errcode,
	})
}

func (h *ProfileHandler) ChangeSystemUserPassword(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	//username := c.Param("name")
	//password := mapToken["password"]
}


func (h *ProfileHandler) DeleteSystemUser(c *gin.Context) {
	username := c.Param("name")
	log.Println(fmt.Sprintf("Delete system user: %s", username))

	command := fmt.Sprintf("userdel -r %s", username)
	res := <-ExecuteCommandAsync(command)
	c.JSON(http.StatusCreated, gin.H{
		"error": res.errcode,
	})
}

func (h *ProfileHandler) CreateDatabase(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	name := mapToken["name"]
	encoding := mapToken["encoding"]

	query := fmt.Sprintf("CREATE DATABASE %s /*\\!40100 DEFAULT CHARACTER SET %s */;", name, encoding)
	log.Println(query)
	res := <-ExecuteMySQLQueryAsync(query)
	c.JSON(http.StatusCreated, gin.H{
		"error": res.errcode,
	})
}

func (h *ProfileHandler) DeleteDatabase(c *gin.Context) {
	name := c.Param("name")
	log.Println(fmt.Sprintf("Delete Database: %s", name))

	query := fmt.Sprintf("DROP DATABASE %s;", name)
	log.Println(query)
	res := <-ExecuteMySQLQueryAsync(query)
	c.JSON(http.StatusCreated, gin.H{
		"error": res.errcode,
	})
}

func (h *ProfileHandler) CreateDatabaseUser(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	name := mapToken["name"]
	password := mapToken["password"]

	//CREATE USER ${MAINDB}@localhost IDENTIFIED BY '${PASSWDDB}';
	var query = fmt.Sprintf("CREATE USER '%s'@'localhost' IDENTIFIED BY '%s';GRANT ALL PRIVILEGES ON *.* TO '%s'@'localhost';FLUSH PRIVILEGES;", name, password, name)
	log.Println(query)
	res := <-ExecuteMySQLQueryAsync(query)
	c.JSON(http.StatusCreated, gin.H{
		"error": res.errcode,
	})
}

func (h *ProfileHandler) DeleteDatabaseUser(c *gin.Context) {
	name := c.Param("name")
	log.Println(fmt.Sprintf("Delete Database User: %s", name))

	//DROP USER 'bloguser'@'localhost';
	var query = fmt.Sprintf("DROP USER '%s'@'localhost';", name)
	log.Println(query)
	res := <-ExecuteMySQLQueryAsync(query)
	c.JSON(http.StatusCreated, gin.H{
		"error": res.errcode,
	})
}

func (h *ProfileHandler) ChangePhpVersion(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	php_version := mapToken["php_version"]
	log.Println(fmt.Sprintf("Change PHP version, php_version: %s", php_version))

	result := ExecuteCommand("update-alternatives --set php /usr/bin/" + php_version)
	if !result {
		c.JSON(http.StatusCreated, map[string]bool{
			"success": false,
		})
		return
	}

	c.JSON(http.StatusCreated, map[string]bool{
		"success": true,
	})
}

func exists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func (h *ProfileHandler) AddSSHKey(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	userName := mapToken["userName"]
	pubKey := mapToken["pubKey"]
	if len(userName) <= 0 || len(pubKey) <= 0 {
		c.JSON(http.StatusUnprocessableEntity, "Invalid params")
		return
	}
	log.Println(fmt.Sprintf("AddSSHKey %s %s", userName, pubKey))

	var folderPath = fmt.Sprintf("/home/%s/.ssh", userName)
	if !exists(folderPath) {
		log.Println("AddSSHKey, createfolder")
		err := os.MkdirAll(folderPath, os.ModePerm)
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, err.Error())
			return
		}
	}

	var filePath = fmt.Sprintf("%s/authorized_keys", folderPath)
	log.Println(fmt.Sprintf("AddSSHKey, FilePath %s", filePath))
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Println("AddSSHKey, failed to open file authorized_keys")
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	defer f.Close()
	if _, err := f.WriteString(fmt.Sprintf("%s\n", pubKey)); err != nil {
		log.Println("AddSSHKey, failed to write key")
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"error": 0,
	})

	/*is_vaulted, _ := strconv.ParseBool(mapToken["is_vaulted"])
	username := mapToken["user"]
	_ = mapToken["label"]

	bitSize := 3072
	if is_vaulted {
		privateKey, err := generatePrivateKey(bitSize)
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, err.Error())
			return
		}

		publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, err.Error())
			return
		}

		privateKeyBytes := encodePrivateKeyToPEM(privateKey)

		stringPrivate := string(privateKeyBytes[:])
		stringPublic := string(publicKeyBytes[:])

		if !exists("/home/" + username + "/.ssh") {
			ExecuteCommand("mkdir /home/" + username + "/.ssh")
		}

		ExecuteCommand("echo '" + stringPublic + "' >> /home/" + username + "/.ssh/authorized_keys")
		fmt.Println("echo '" + stringPublic + "' >> /home/" + username + "/.ssh/authorized_keys")
		c.JSON(http.StatusCreated, map[string]string{
			"success":     strconv.FormatBool(true),
			"private_key": stringPrivate,
		})
	} else {
		public_key := mapToken["public_key"]

		if !exists("/home/" + username + "/.ssh") {
			ExecuteCommand("mkdir /home/" + username + "/.ssh")
		}

		ExecuteCommand("echo '" + public_key + "' >> /home/" + username + "/.ssh/authorized_keys")
		fmt.Println("echo '" + public_key + "' >> /home/" + username + "/.ssh/authorized_keys")
		c.JSON(http.StatusCreated, map[string]string{
			"success": strconv.FormatBool(true),
		})
	}*/
}

func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		log.Println("PrivateKeyGen, error: %d", err.Error())
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		log.Println("PrivateKeyGen, validate-error: %d", err.Error())
		return nil, err
	}

	log.Println("PrivateKey generated")
	return privateKey, nil
}

// take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		log.Println("PublicKeyGen-error-1")
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)
	log.Println("Public key generated")
	return pubKeyBytes, nil
}

// encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		log.Println("writeKeyToFile, err: %d", err.Error())
		return err
	}

	log.Printf("Key saved to: %s", saveFileTo)
	return nil
}

func (h *ProfileHandler) AddDeploymentKey(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	userName := mapToken["userName"]
	if len(userName) <= 0 {
		c.JSON(http.StatusUnprocessableEntity, "Invalid params")
		return
	}

	if !exists("/home/" + userName) {
		log.Println("AddDeploymentKey, the user doen not exists")
		c.JSON(http.StatusCreated, gin.H{
			"error": -10,
		})
	}

	sshKeyPath := "/home/" + userName + "/.ssh"
	privateKeyPath := sshKeyPath + "/id_rsa"
	publicKeyPath := sshKeyPath + "/id_rsa.pub"

	privateKey, err := generatePrivateKey(3072)
	if err != nil {
		log.Println("AddDeploymentKey, failed to generate private key")
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Println("AddDeploymentKey, failed to generate public key")
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	if !exists(sshKeyPath) {
		ExecuteCommand("mkdir " + sshKeyPath)
	}

	err = writeKeyToFile(privateKeyBytes, privateKeyPath)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	err = writeKeyToFile([]byte(publicKeyBytes), publicKeyPath)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	myString := string(publicKeyBytes[:])
	////////////////////////////////////////////////////
	c.JSON(http.StatusCreated, gin.H{
		"error": 0,
		"pubKey": myString,
	})
}

func (h *ProfileHandler) CreateCronJob(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	// label := mapToken["label"]
	cron_schedule := mapToken["schedule"]
	cron_job := mapToken["job"]

	var res = <-ExecuteCommandAsync("systemctl enable cron")
	if res.errcode != 0 {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error":   res.errcode,
			"message": "Unable to enable cron service",
		})
		return
	}

	res = <-ExecuteCommandAsync("printf \"\n\" >> /var/spool/cron/crontabs/root")
	if res.errcode != 0 {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error":   res.errcode,
			"message": "Failed to update crontabs",
		})
		return
	}

	var cmd = fmt.Sprintf("printf \"%s %s\" >> /var/spool/cron/crontabs/root", cron_schedule, cron_job)
	res = <-ExecuteCommandAsync(cmd)
	if res.errcode != 0 {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error":   res.errcode,
			"message": "Failed to add cron job",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"error": 0,
	})
}

func (h *ProfileHandler) CreateSuperVisor(c *gin.Context) {
	// should install
	// apt-get install supervisor
	metadata, err := h.tk.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	userId, err := h.rd.FetchAuth(metadata.TokenUuid)
	_ = userId
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	job_name := mapToken["job_name"]
	username := mapToken["user"]
	auto_restart, _ := strconv.ParseBool(mapToken["auto_restart"])
	auto_start, _ := strconv.ParseBool(mapToken["auto_start"])
	num_procs, _ := strconv.Atoi(mapToken["num_procs"])
	vendor_binary := mapToken["vendor_binary"]
	directory := mapToken["directory"]
	command := mapToken["command"]

	if job_name == "" || username == "" || num_procs <= 0 || (vendor_binary == "" && command == "") {
		c.JSON(http.StatusCreated, map[string]bool{
			"success": false,
		})
		return
	}

	if !ExecuteCommand("service supervisor restart") {
		c.JSON(http.StatusCreated, map[string]bool{
			"success": false,
		})
		return
	}

	confFilePath := "/etc/supervisor/conf.d/" + job_name + ".conf"
	var confContent string
	if vendor_binary != "" {
		confContent = "[program:" + job_name + "_vendor]\n" +
			"command=" + vendor_binary + "\n" +
			"user=" + username + "\n" +
			"autostart=" + strconv.FormatBool(auto_start) + "\n" +
			"autorestart=" + strconv.FormatBool(auto_restart) + "\n" +
			"numprocs=" + strconv.Itoa(num_procs) + "\n" +
			"directory=" + directory + "\n"
		if !ExecuteCommand("echo '" + confContent + "' >> " + confFilePath) {
			c.JSON(http.StatusCreated, map[string]bool{
				"success": false,
			})
			return
		}
	}

	if command != "" {
		confContent = "[program:" + job_name + "_command]\n" +
			"command=" + command + "\n"
		if !ExecuteCommand("echo '" + confContent + "' >> " + confFilePath) {
			c.JSON(http.StatusCreated, map[string]bool{
				"success": false,
			})
			return
		}
	}

	c.JSON(http.StatusCreated, map[string]bool{
		"success": true,
	})
}

func (h *ProfileHandler) AddFirewallRule(c *gin.Context) {
	metadata, err := h.tk.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	userId, err := h.rd.FetchAuth(metadata.TokenUuid)
	_ = userId
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	result := true
	if !ExecuteCommand("ufw enable") {
		c.JSON(http.StatusCreated, map[string]bool{
			"success": false,
		})
		return
	}

	f_type := mapToken["type"]
	f_from_port := mapToken["from_port"]
	f_end_port := mapToken["end_port"]
	f_ip_address := mapToken["ip_address"]
	f_protocol := strings.ToLower(mapToken["protocol"])
	f_action := strings.ToLower(mapToken["action"])

	if f_type == "1" {
		fmt.Println("Globally Open Port")
		nStartPort, err := strconv.Atoi(f_from_port)
		if err != nil {
			print("Error: %s", err.Error)
			result = false
		}
		nEndPort, err := strconv.Atoi(f_end_port)
		if err != nil {
			print("Error: %s", err.Error)
			result = false
		}
		if result {
			if nEndPort == 0 {
				com := "ufw allow " + f_from_port + "/" + f_protocol
				print(com)
				result = ExecuteCommand(com)
			} else {
				for i := nStartPort; i <= nEndPort; i++ {
					com := "ufw allow " + strconv.Itoa(i) + "/" + f_protocol
					print(com)
					result = ExecuteCommand(com)
					if !result {
						break
					}
				}
			}
		}

	} else {
		fmt.Println("Rich Rule")
		nStartPort, err := strconv.Atoi(f_from_port)
		if err != nil {
			print("Error: %s", err.Error)
			result = false
		}
		nEndPort, err := strconv.Atoi(f_end_port)
		if err != nil {
			print("Error: %s", err.Error)
			result = false
		}
		if result {
			if nEndPort == 0 {
				com := "ufw " + f_action + " from " + f_ip_address + " port " + f_from_port + " proto " + f_protocol
				print(com)
				result = ExecuteCommand(com)
			} else {
				for i := nStartPort; i <= nEndPort; i++ {
					com := "ufw " + f_action + " from " + f_ip_address + " port " + strconv.Itoa(i) + " proto " + f_protocol
					print(com)
					result = ExecuteCommand(com)
					if !result {
						break
					}
				}
			}
		}
	}

	c.JSON(http.StatusCreated, map[string]bool{
		"success": result,
	})
}

func ExecuteCommand_WithResult(command string) (string, error) {

	// cmd := exec.Command("sh", "-c", "systemctl list-units --all --type=service --no-pager | grep -i 'redis'")
	// cmd := exec.Command("sh", "-c", "systemctl status redis-server | grep 'Main PID:'")
	// cmd := exec.Command("sh", "-c", "dpkg -s redis-server | grep Version")
	// cmd := exec.Command("sh", "-c", "pidstat -p 864 -r | grep 864")
	// cmd := exec.Command("sh", "-c", "pidstat -p 864 -u | grep 864")
	cmd := exec.Command("sh", "-c", command)
	stdoutStderr, err := cmd.CombinedOutput()

	if err != nil {
		return "", err
	}

	var strReturn = strings.TrimSpace(string(stdoutStderr))
	return strReturn, err
}

func (h *ProfileHandler) ViewServices(c *gin.Context) {
	var command = "systemctl -t service | grep -E '\\.service' | sed 's/^\\s*//g'"
	res := <-ExecuteCommandAsync(command)
	if res.errcode != 0 {
		c.JSON(http.StatusCreated, gin.H{
			"error": res.errcode,
		})
		return
	}

	// mariadb
	items := strings.Split(res.result, "\n")
	for i, s := range items {
		var service = strings.TrimSpace(s)
		service = strings.ReplaceAll(service, "  ", "")
		var nodes = strings.Split(service, " ")
		fmt.Println(i, nodes)
	}

	c.JSON(http.StatusCreated, gin.H{
		"error": res.errcode,
	})

	/*type StructService struct {
		Process string `json:"process"`
		Name    string `json:"name"`
		Version string `json:"version"`
		State   string `json:"state"`
		Cpu     string `json:"cpu"`
		Mem     string `json:"mem"`
	}

	var serviceArray [4]StructService
	var processName string
	var processID string

	// apache
	nIndex := 0
	serviceArray[nIndex].Name = "HTTPD/APACHE"
	strTemp, _ := ExecuteCommand_WithResult("systemctl list-units --all --type=service --no-pager | grep -i 'apache'")
	if strTemp != "" {
		arrayStringTemp := strings.Fields(strTemp)
		serviceArray[nIndex].Process = strings.ReplaceAll(arrayStringTemp[0], ".service", "")
		serviceArray[nIndex].State = arrayStringTemp[3]
		processName = serviceArray[nIndex].Process

		strTemp, _ = ExecuteCommand_WithResult("dpkg -s " + processName + " | grep Version")
		if strTemp != "" {
			serviceArray[nIndex].Version = strings.ReplaceAll(strTemp, "Version: ", "")
		}

		if arrayStringTemp[3] == "running" {
			strTemp, _ = ExecuteCommand_WithResult("systemctl status " + processName + " | grep 'Main PID:'")
			if strTemp != "" {
				arrayStringTemp = strings.Fields(strings.ReplaceAll(strTemp, "Main PID: ", ""))
				processID = arrayStringTemp[0]
			}

			if processID != "" {
				strTemp, _ = ExecuteCommand_WithResult("pidstat -u | grep " + processID)
				if strTemp != "" {
					arrayStringTemp = strings.Fields(strTemp)
					serviceArray[nIndex].Cpu = arrayStringTemp[7]
				}
			}

			if processID != "" {
				strTemp, _ = ExecuteCommand_WithResult("pidstat -r | grep " + processID)
				if strTemp != "" {
					arrayStringTemp = strings.Fields(strTemp)
					serviceArray[nIndex].Mem = arrayStringTemp[7]
				}
			}
		}
	}

	// mariadb
	// should change mariadb-server in getting pid
	processID = ""
	nIndex++
	serviceArray[nIndex].Name = "MARIADB"
	strTemp, _ = ExecuteCommand_WithResult("systemctl list-units --all --type=service --no-pager | grep -i 'mariadb'")
	if strTemp != "" {
		arrayStringTemp := strings.Fields(strTemp)
		serviceArray[nIndex].Process = strings.ReplaceAll(arrayStringTemp[0], ".service", "")
		serviceArray[nIndex].State = arrayStringTemp[3]
		processName = serviceArray[nIndex].Process

		strTemp, _ = ExecuteCommand_WithResult("dpkg -s mariadb-server | grep Version")
		if strTemp != "" {
			serviceArray[nIndex].Version = strings.ReplaceAll(strTemp, "Version: ", "")
		}

		if arrayStringTemp[3] == "running" {
			strTemp, _ = ExecuteCommand_WithResult("systemctl status " + processName + " | grep 'Main PID:'")
			if strTemp != "" {
				arrayStringTemp = strings.Fields(strings.ReplaceAll(strTemp, "Main PID: ", ""))
				processID = arrayStringTemp[0]
			}

			if processID != "" {
				strTemp, _ = ExecuteCommand_WithResult("pidstat -u | grep " + processID)
				if strTemp != "" {
					arrayStringTemp = strings.Fields(strTemp)
					serviceArray[nIndex].Cpu = arrayStringTemp[7]
				}
			}

			if processID != "" {
				strTemp, _ = ExecuteCommand_WithResult("pidstat -r | grep " + processID)
				if strTemp != "" {
					arrayStringTemp = strings.Fields(strTemp)
					serviceArray[nIndex].Mem = arrayStringTemp[7]
				}
			}
		}
	}

	// redis
	processID = ""
	nIndex++
	serviceArray[nIndex].Name = "REDIS"
	strTemp, _ = ExecuteCommand_WithResult("systemctl list-units --all --type=service --no-pager | grep -i 'redis'")
	if strTemp != "" {
		arrayStringTemp := strings.Fields(strTemp)
		serviceArray[nIndex].Process = strings.ReplaceAll(arrayStringTemp[0], ".service", "")
		serviceArray[nIndex].State = arrayStringTemp[3]
		processName = serviceArray[nIndex].Process

		strTemp, _ = ExecuteCommand_WithResult("dpkg -s " + processName + " | grep Version")
		if strTemp != "" {
			serviceArray[nIndex].Version = strings.ReplaceAll(strTemp, "Version: ", "")
		}

		if arrayStringTemp[3] == "running" {
			strTemp, _ = ExecuteCommand_WithResult("systemctl status " + processName + " | grep 'Main PID:'")
			if strTemp != "" {
				arrayStringTemp = strings.Fields(strings.ReplaceAll(strTemp, "Main PID: ", ""))
				processID = arrayStringTemp[0]
			}

			if processID != "" {
				strTemp, _ = ExecuteCommand_WithResult("pidstat -u | grep " + processID)
				if strTemp != "" {
					arrayStringTemp = strings.Fields(strTemp)
					serviceArray[nIndex].Cpu = arrayStringTemp[7]
				}
			}

			if processID != "" {
				strTemp, _ = ExecuteCommand_WithResult("pidstat -r | grep " + processID)
				if strTemp != "" {
					arrayStringTemp = strings.Fields(strTemp)
					serviceArray[nIndex].Mem = arrayStringTemp[7]
				}
			}
		}
	}

	// supervisor
	processID = ""
	nIndex++
	serviceArray[nIndex].Name = "SUPERVISOR"
	strTemp, _ = ExecuteCommand_WithResult("systemctl list-units --all --type=service --no-pager | grep -i 'supervisor'")
	if strTemp != "" {
		arrayStringTemp := strings.Fields(strTemp)
		serviceArray[nIndex].Process = strings.ReplaceAll(arrayStringTemp[0], ".service", "")
		serviceArray[nIndex].State = arrayStringTemp[3]
		processName = serviceArray[nIndex].Process

		strTemp, _ = ExecuteCommand_WithResult("dpkg -s " + processName + " | grep Version")
		if strTemp != "" {
			serviceArray[nIndex].Version = strings.ReplaceAll(strTemp, "Version: ", "")
		}

		if arrayStringTemp[3] == "running" {
			strTemp, _ = ExecuteCommand_WithResult("systemctl status " + processName + " | grep 'Main PID:'")
			if strTemp != "" {
				arrayStringTemp = strings.Fields(strings.ReplaceAll(strTemp, "Main PID: ", ""))
				processID = arrayStringTemp[0]
			}

			if processID != "" {
				strTemp, _ = ExecuteCommand_WithResult("pidstat -u | grep " + processID)
				if strTemp != "" {
					arrayStringTemp = strings.Fields(strTemp)
					serviceArray[nIndex].Cpu = arrayStringTemp[7]
				}
			}

			if processID != "" {
				strTemp, _ = ExecuteCommand_WithResult("pidstat -r | grep " + processID)
				if strTemp != "" {
					arrayStringTemp = strings.Fields(strTemp)
					serviceArray[nIndex].Mem = arrayStringTemp[7]
				}
			}
		}
	}

	services, _ := json.Marshal(serviceArray)

	c.JSON(http.StatusCreated, map[string]string{
		"success":  "true",
		"services": string(services),
		// "temp": strTemp,
	})*/
}

func DownloadFile(filepath string, url string) error {
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}


func (h *ProfileHandler) InstallWordpress(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	appName := mapToken["name"]
	userName := mapToken["userName"]
	domain := mapToken["domainName"]
	webserver := mapToken["webserver"]
	phpVersion := mapToken["phpVersion"]
	siteTitle := mapToken["siteTitle"]
	adminEmail := mapToken["adminEmail"]
	adminUser := mapToken["adminUserName"]
	adminPass := mapToken["adminPassword"]
	dbuser := mapToken["databaseUser"]
	dbname := mapToken["databaseName"]
	dbpass := mapToken["databasePass"]
	dbprefix := mapToken["tablePrefix"]

	if len(dbprefix) <= 0 {
		dbprefix = "wp_"
	}

	log.Println(fmt.Sprintf("InstallWordpress(1) %s %s", appName, userName))
	log.Println(fmt.Sprintf("InstallWordpress(1) %s %s %s", domain, phpVersion, siteTitle))
	log.Println(fmt.Sprintf("InstallWordpress(1) %s %s %s", adminEmail, adminUser, adminPass))
	log.Println(fmt.Sprintf("InstallWordpress(1) %s %s %s %s", dbuser, dbname, dbpass, dbprefix))

	if len(appName) <= 0 || len(userName) <= 0 || len(webserver) <= 0 || len(phpVersion) <= 0 || len(siteTitle) <= 0 || len(adminUser) <= 0 || len(adminPass) <= 0 || len(adminEmail) <= 0 {
		c.JSON(http.StatusUnprocessableEntity, "Invalid params")
		return
	}

	_, err := user.Lookup(userName)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Failed to get user id")
		return
	}

	// Restart nginx service
	cmd := fmt.Sprintf("/litegix/litegix-agent/inswp.sh %s %s %s %s %s %s %s %s %s %s %s %s",
		userName, appName, siteTitle, domain, adminUser, adminEmail, adminPass, dbuser, dbname, dbpass, dbprefix, webserver);
	res := <-ExecuteCommandAsync(cmd)
	if res.errcode != 0 {
		c.JSON(http.StatusCreated, gin.H{
			"error": res.errcode,
			"msg": "Failed to install wordpress",
		})
		return
	}

	// Success
	c.JSON(http.StatusCreated, gin.H{
		"error": 0,
	})
}

func (h *ProfileHandler) InstallSSL(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	domain := mapToken["domain"]
	email := mapToken["email"]
	log.Println(fmt.Sprintf("InstallSSL %s %s", domain, email))

	if len(domain) <= 0 || len(email) <= 0 {
		c.JSON(http.StatusUnprocessableEntity, "Invalid params")
		return
	}

	cmd := fmt.Sprintf("/litegix/litegix-agent/inscert.sh %s %s", domain, email);
	res := <-ExecuteCommandAsync(cmd)
	if res.errcode != 0 {
		c.JSON(http.StatusCreated, gin.H{
			"error": res.errcode,
			"msg": "Failed to install ssl",
		})
		return
	}

	// Success
	c.JSON(http.StatusCreated, gin.H{
		"error": 0,
	})
}
