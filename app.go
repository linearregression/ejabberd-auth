package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"github.com/go-redis/redis"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type ConfigStruct struct {
	LogFile string `json:"log_file"`
	Redis   struct {
		Addr     string `json:"addr"`
		Password string `json:"password"`
		DB       int64  `json:"db"`
		PoolSize int    `json:"pool_size"`
	} `json:"redis"`
	Keys map[string]string `json:"keys"`
}

/* https://www.ejabberd.im/files/doc/dev.html#htoc8 */
var Redis *redis.Client
var Config *ConfigStruct

func fromEjabberd(stdin *os.File) ([]string, error) {

	length := make([]byte, 2)
	size, err := stdin.Read(length)
	if err != nil {
		return nil, err
	}
	val := binary.BigEndian.Uint16(length)

	data := make([]byte, val)
	size, err = stdin.Read(data)
	if uint16(size) != val {
		return nil, errors.New("bad length data")
	}
	if err != nil {
		return nil, err
	}
	return strings.Split(string(data), ":"), nil
}

func toEjabberd(stdout *os.File, result bool) {

	if result == true {
		stdout.Write([]byte{0, 2, 0, 1})
		return
	}
	stdout.Write([]byte{0, 2, 0, 0})
}

func encrypt(message string, secret string) string {

	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func Auth(username string, server string, password string) bool {

	log.Println("info:", "Auth user ", username, server)

	key := server + ":" + username
	yes, err := Redis.Exists(key).Result()
	if err != nil {
		log.Println("error:", "Auth: ", err)
		return false
	}
	if !yes {
		log.Println("info:", "unknown user...")
		return false
	}

	hmac_passwd, err := Redis.HGet(key, "password").Result()
	if err != nil {
		log.Println("error:", "Auth: ", err)
		return false
	}

	if encrypt(username+";"+server, password) == hmac_passwd {
		return true
	}

	params := strings.Split(password, ";")
	if len(params) != 3 {
		log.Println("info:", "invalid auth token, len(params) != 3")
		return false
	}
	pubKey := params[1]

	if _, ok := Config.Keys[pubKey]; !ok {
		log.Println("info:", "invalid public key: ", pubKey)
		return false
	}

	private_key := Config.Keys[pubKey]

	token := params[0]
	timestamp := params[2]

	tokenExpected := encrypt(timestamp+";"+username, private_key)

	return token == tokenExpected
}

func IsUser(username string, server string) bool {

	log.Println("info:", "IsUser user ", username, server)

	key := server + ":" + username

	yes, err := Redis.Exists(key).Result()
	if err != nil {

		log.Println("error:", "IsUser: ", err)
		return false
	}

	return yes
}

func SetPass(username string, server string, password string) bool {

	return true
}

func TryRegister(username string, server string, password string) bool {

	log.Println("info:", "TryRegister user ", username, server)

	key := server + ":" + username

	yes, err := Redis.Exists(key).Result()
	if err != nil {
		log.Println("error:", "TryRegister: ", err)
		return false
	}

	if !yes {
		err = Redis.HMSet(key, "username", username, "password", encrypt(username+";"+server, password)).Err()
		if err != nil {
			log.Println("error:", "TryRegister: ", err)
			return false
		}
		return true
	}

	return false
}

func RemoveUser(username string, server string) bool {

	return false
}

func RemoveUser3(username string, server string, password string) bool {

	return false
}

func readConfig(configFile string) {

	log.Println("info:", "Using configuration file: ", configFile)
	file, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalln("fatal:", err)
	}

	Config = new(ConfigStruct)
	if err := json.Unmarshal(file, Config); err != nil {

		log.Fatalln("fatal:", "Fail to load config: ", err)
	}
}

func main() {

	var configFile string
	flag.StringVar(&configFile, "config", "ejabberd-auth.conf", "Ejabberd Auth configuration file")
	flag.Parse()

	readConfig(configFile)

	f, err := os.OpenFile(Config.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalln("fatal:", err)
	}
	defer f.Close()

	log.SetOutput(f)

	stdin := os.Stdin
	stdout := os.Stdout

	log.Println("info:", "Connecting to redis...")
	Redis = redis.NewClient(&redis.Options{
		Network:  "tcp",
		Addr:     Config.Redis.Addr,
		Password: Config.Redis.Password,
		DB:       Config.Redis.DB,
		PoolSize: Config.Redis.PoolSize,
	})

	running := true

	for running {

		result := false
		args, err := fromEjabberd(stdin)
		if err != nil {
			if err == io.EOF {
				running = false
			} else {
				toEjabberd(stdout, result)
				return
			}
		} else {
			if args[0] == "auth" && len(args) == 4 {
				result = Auth(args[1], args[2], args[3])
			} else if args[0] == "isuser" && len(args) == 3 {
				result = IsUser(args[1], args[2])
			} else if args[0] == "setpass" && len(args) == 4 {
				result = SetPass(args[1], args[2], args[3])
			} else if args[0] == "tryregister" && len(args) == 4 {
				result = TryRegister(args[1], args[2], args[3])
			} else if args[0] == "removeuser" && len(args) == 3 {
				result = RemoveUser(args[1], args[2])
			} else if args[0] == "removeuser3" && len(args) == 4 {
				result = RemoveUser3(args[1], args[2], args[3])
			} else {
				log.Println("error:", "unknown command: ", args[0])
				continue
			}
			toEjabberd(stdout, result)
		}
	}
}
