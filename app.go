package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gosexy/redis"
	"io"
	"log"
	"os"
	"strings"
)

/* https://www.ejabberd.im/files/doc/dev.html#htoc8 */
var Redis *redis.Client
var Public_key string
var Private_key string

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

func Auth(username string, server string, password string) bool {

	key := server + ":" + username
	yes, err := Redis.Exists(key)
	if err != nil || yes == false {
		return false
	}

	params := strings.Split(password, ";")
	if len(params) != 3 {
		return false
	}
	pubKey := params[1]
	if pubKey != Public_key {
		return false
	}
	token, _ := hex.DecodeString(params[0])
	timestamp := params[2]

	hasher := hmac.New(sha256.New, []byte(Private_key))
	hasher.Write([]byte(timestamp + ";" + username))
	tokenExpected := hasher.Sum(nil)

	return hmac.Equal(token, tokenExpected)
}

func IsUser(username string, server string) bool {

	key := server + ":" + username

	yes, err := Redis.Exists(key)
	if err != nil {
		return false
	}

	return yes
}

func SetPass(username string, server string, password string) bool {

	return true
}

func TryRegister(username string, server string, password string) bool {

	key := server + ":" + username

	yes, err := Redis.Exists(key)
	if err != nil {
		return false
	}

	if !yes {
		_, err = Redis.Set(key, `{"username": "`+username+`"}`)
		if err != nil {
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

func main() {

	f, err := os.OpenFile("debug.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()

	log.SetOutput(f)
	log.Println("This is a test log entry")

	stdin := os.Stdin
	stdout := os.Stdout

	Redis = redis.New()
	err = Redis.Connect("172.16.23.128", 6379)
	if err != nil {
		fmt.Println(err)
	}

	Public_key = "ceci_est_ma_public_key"
	Private_key = "ceci_est_ma_private_key"

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
			}
			toEjabberd(stdout, result)
		}
	}
}
