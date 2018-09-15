package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"github.com/atotto/clipboard"
	"github.com/urfave/cli"
	"io/ioutil"
	"os/user"
	"path"
	"sort"
	"strconv"
	"strings"
)

type Config struct {
	Key      string
	HashKey  string
	HashSalt string
	Items    map[string]string
}

var (
	configPath = ""
)

func init() {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	configPath = path.Join(usr.HomeDir, ".tfat/tfat.conf")
}

func checkResult(err error, errMsg string) {
	if err != nil {
		log.Fatal(errMsg, err)
	}
}

func getUserInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s: ", prompt)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

func readConfig() (Config, error) {
	if _, err := os.Stat(configPath); err == nil {
		var buf bytes.Buffer
		confBytes, err := ioutil.ReadFile(configPath)
		if err != nil {
			return Config{}, errors.New("read config file error")
		}
		saltStr := string(confBytes[:PwSaltLength])
		keyStr := string(confBytes[PwSaltLength : PwSaltLength+PwLength])
		plainStr := getUserInput("Input Password")
		if !verifyPassword(plainStr, saltStr, keyStr) {
			log.Fatal("Invalid password")
		}
		contentByte, err := hex.DecodeString(string(confBytes[PwSaltLength+PwLength:]))
		checkResult(err, "decode content failed:")
		md5Key := md5.Sum([]byte(plainStr))
		origData, err := AesDecrypt(contentByte, md5Key[:])
		checkResult(err, "decrypt failed:")

		buf.Write(origData)
		dec := gob.NewDecoder(&buf)
		var result Config
		if err := dec.Decode(&result); err != nil {
			log.Fatal("decode error:", err)
		}
		return result, nil
	} else {
		os.MkdirAll(path.Dir(configPath), os.ModePerm)
	}
	return Config{}, errors.New("read config file error")
}

func saveConfig(config *Config) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(config); err != nil {
		log.Fatal("encode error:", err)
	}
	md5Key := md5.Sum([]byte(config.Key))
	result, err := AesEncrypt(buf.Bytes(), md5Key[:])
	checkResult(err, "encrypt failed: ")
	outStr := config.HashSalt + config.HashKey + fmt.Sprintf("%X", result)
	err = ioutil.WriteFile(configPath, []byte(outStr), 0600)
	checkResult(err, "save config file failed:")
}

func addOrModifyItem(name, secret string) error {
	if len(name) == 0 || len(secret) == 0 {
		log.Fatal("Invalid arguments")
	}

	config, err := readConfig()
	if err != nil {
		config.Key = ""
		for len(config.Key) == 0 {
			config.Key = getUserInput("Input password")
		}
		config.HashKey, config.HashSalt = hashPassword(config.Key)
		config.Items = make(map[string]string)
	}
	config.Items[name] = strings.ToUpper(strings.TrimSpace(secret))

	saveConfig(&config)

	fmt.Println("Add success!")
	return nil
}

func listItem() {
	config, err := readConfig()
	checkResult(err, "Read config failed")

	idx := 1
	for k := range config.Items {
		fmt.Printf("%d. %s\n", idx, k)
		idx++
	}
}

func deleteItem(name string) {
	config, err := readConfig()
	checkResult(err, "Read config failed")

	delete(config.Items, name)
	saveConfig(&config)

	fmt.Println("Delete success!")
}

func changePassword(plainPwd string) {
	config, err := readConfig()
	checkResult(err, "Read config failed")

	config.Key = plainPwd
	config.HashKey, config.HashSalt = hashPassword(config.Key)

	saveConfig(&config)

	fmt.Println("Change success!")
}

func getCode() {
	config, err := readConfig()
	checkResult(err, "Read config failed, run 'tfat help' for help")

	var names []string
	idx := 1
	for k := range config.Items {
		names = append(names, k)
		fmt.Printf("%d. %s\n", idx, k)
		idx++
	}
	if len(names) <= 0 {
		log.Fatal("There is no item in config, run 'tfat help' for help")
	} else if len(names) > 1 {
		idx, err = strconv.Atoi(getUserInput("Enter index"))
		if err != nil || idx < 1 || idx > len(names) {
			log.Fatal("Invalid input", err)
		}
	} else {
		idx = 1
	}
	keyStr := config.Items[names[idx-1]]

	var lastCode uint32 = 0
	for true {
		pwd, err := OneTimePassword(keyStr)
		checkResult(err, "Get code ERROR: ")

		secondsRemaining := 30 - (time.Now().Unix() % 30)
		fmt.Printf("\r%06d (expires in %ds) ", pwd, secondsRemaining)
		if lastCode != pwd {
			lastCode = pwd
			clipboard.WriteAll(fmt.Sprintf("%06d", pwd))
		}
		time.Sleep(1 * time.Second)
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "Two Factor Authentication(2FA) Tool"
	app.Usage = "Help to generate 2FA code"
	app.Version = "0.0.1"
	app.Commands = []cli.Command{
		{
			Name:      "list",
			UsageText: "tfat list",
			Usage:     "List all items",
			Action: func(c *cli.Context) error {
				listItem()
				return nil
			},
		},
		{
			Name:      "add",
			UsageText: "tfat add <NAME> <KEY>",
			Usage:     "Add a new item",
			Action: func(c *cli.Context) error {
				if len(c.Args()) < 2 {
					log.Fatal("Invalid arguments, see 'go help add'")
				}
				item := c.Args().First()
				secret := c.Args()[1]
				addOrModifyItem(item, secret)
				return nil
			},
		},
		{
			Name:      "delete",
			UsageText: "tfat delete <NAME>",
			Usage:     "Delete an item",
			Action: func(c *cli.Context) error {
				if len(c.Args()) < 1 {
					log.Fatal("Invalid arguments, see 'go help delete'")
				}
				deleteItem(c.Args().First())
				return nil
			},
		}, {
			Name:      "password",
			UsageText: "tfat password <PASSWORD>",
			Usage:     "Change password",
			Action: func(c *cli.Context) error {
				if len(c.Args()) < 1 {
					log.Fatal("Invalid arguments, see 'go help password'")
				}
				changePassword(c.Args().First())
				return nil
			},
		},
	}
	app.Action = func(c *cli.Context) error {
		getCode()
		return nil
	}

	sort.Sort(cli.FlagsByName(app.Flags))

	cli.HelpFlag = cli.BoolFlag{
		Name:  "help, h",
		Usage: "Show this help",
	}

	cli.VersionFlag = cli.BoolFlag{
		Name:  "version, v",
		Usage: "Print version",
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
