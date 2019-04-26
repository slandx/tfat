package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	// UserPwd 用户指定密码
	UserPwd = 1
	// DefaultPwd 自动生成密码
	DefaultPwd        = 2
	aesKeySize uint32 = 32
	nonceSize         = 12
)

// Config 配置类结构体
type Config struct {
	IsNew    bool
	Pwd      []byte
	PwdType  int
	Accounts map[string]string
}

var (
	configPath          = ""
	errInvalidDataFile  = errors.New("invalid data file")
	errWrongPassword    = errors.New("wrong password")
	errInternalIoFailed = errors.New("internal i/o failed")
)

func init() {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	configPath = path.Join(usr.HomeDir, ".tfat/tfat.dat")
}

func readConfig() (Config, error) {
	if _, err := os.Stat(configPath); err == nil {
		confBytes, err := ioutil.ReadFile(configPath)
		if err != nil || len(confBytes) < (nonceSize+1) {
			return Config{}, errInvalidDataFile
		}
		var result Config
		nonce := confBytes[:nonceSize]
		result.PwdType = int(confBytes[nonceSize])
		encryptedBytes := confBytes[nonceSize+1:]
		if result.PwdType == UserPwd {
			result.Pwd = []byte(getUserInput("Input password", true))
		} else if result.PwdType == DefaultPwd {
			result.Pwd = nonce
		} else {
			return Config{}, errInvalidDataFile
		}

		key := deriveKey(result.Pwd, nonce, aesKeySize)
		block, err := aes.NewCipher(key)
		if err != nil {
			return Config{}, errWrongPassword
		}

		aesGcm, err := cipher.NewGCM(block)
		if err != nil {
			return Config{}, errWrongPassword
		}

		decryptedData, err := aesGcm.Open(nil, nonce, encryptedBytes, nil)
		if err != nil {
			return Config{}, errWrongPassword
		}

		_, err = toml.Decode(string(decryptedData), &result.Accounts)
		if err != nil {
			return Config{}, errInvalidDataFile
		}
		return result, nil
	}
	os.MkdirAll(path.Dir(configPath), os.ModePerm)
	return Config{IsNew: true}, nil
}

func saveConfig(config *Config) error {
	var buf bytes.Buffer

	nonce := make([]byte, nonceSize)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return errInternalIoFailed
	}

	buf.Write(nonce)
	buf.WriteByte(byte(config.PwdType))

	if config.PwdType == DefaultPwd {
		config.Pwd = nonce
	}

	key := deriveKey(config.Pwd, nonce, aesKeySize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return errWrongPassword
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return errWrongPassword
	}

	tomlBuf := &bytes.Buffer{}
	encoder := toml.NewEncoder(tomlBuf)
	err = encoder.Encode(config.Accounts)
	if err != nil {
		return errInternalIoFailed
	}
	encryptedData := aesGcm.Seal(nil, nonce, tomlBuf.Bytes(), nil)

	buf.Write(encryptedData)
	err = ioutil.WriteFile(configPath, buf.Bytes(), 0600)
	if err != nil {
		return errInternalIoFailed
	}
	return nil
}

func getUserInput(prompt string, isPassword bool) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s: ", prompt)
	if isPassword {
		bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		return string(bytePassword)
	}
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

func initPassword(cfg *Config) error {
	retryTimes := 3
	for retryTimes > 0 {
		fmt.Printf("New password: ")
		newPwd, _ := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\nConfirm password: ")
		confirmPwd, _ := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if bytes.Equal(newPwd, confirmPwd) {
			cfg.Pwd = newPwd
			if len(newPwd) == 0 {
				cfg.PwdType = DefaultPwd
			} else {
				cfg.PwdType = UserPwd
			}
			return nil
		}
		retryTimes--
		fmt.Println("Different password, try again!")
	}
	return errWrongPassword
}
