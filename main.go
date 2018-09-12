package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"github.com/atotto/clipboard"
	"github.com/urfave/cli"
	"io/ioutil"
	"math/rand"
	"os/user"
	"path"
	"sort"
	"strconv"
	"strings"
)

type Config struct {
	Secret string
	Items  map[string]string
}

const letterBytes = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"

var (
	configPath = ""
	secretLen  = 16
)

func init() {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	configPath = path.Join(usr.HomeDir, ".tfat/tfat.conf")
}

func randomString(n int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func readConfig() (Config, error) {
	if _, err := os.Stat(configPath); err == nil {
		var buf bytes.Buffer
		confBytes, err := ioutil.ReadFile(configPath)
		if err != nil {
			return Config{}, errors.New("read config file error")
		}
		binContent, err := hex.DecodeString(string(confBytes[secretLen:]))
		if err != nil {
			log.Fatal("hex decode error:", err)
		}
		origData, err := AesDecrypt(binContent, confBytes[:secretLen])
		if err != nil {
			log.Fatal("decrypt failed:", err)
		}
		buf.Write(origData)
		dec := gob.NewDecoder(&buf)
		var result Config
		if err := dec.Decode(&result); err != nil {
			log.Fatal("decode error:", err)
		}
		return result, nil
	} else {
		os.MkdirAll(path.Dir(configPath), os.ModeDir)
	}
	return Config{}, errors.New("read config file error")
}

func saveConfig(config *Config) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(config); err != nil {
		log.Fatal("encode error:", err)
	}
	result, err := AesEncrypt(buf.Bytes(), []byte(config.Secret))
	if err != nil {
		log.Fatal("encrypt failed:", err)
	}
	outStr := config.Secret + fmt.Sprintf("%X", result)
	err = ioutil.WriteFile(configPath, []byte(outStr), 0666)
	if err != nil {
		log.Fatal("save config file failed:", err)
	}
}

func addOrModifyItem(name, secret string) error {
	if len(name) == 0 || len(secret) == 0 {
		log.Fatal("Invalid arguments")
	}

	config, err := readConfig()
	if err != nil {
		config.Secret = randomString(16)
		config.Items = make(map[string]string)
	}
	config.Items[name] = strings.ToUpper(strings.TrimSpace(secret))

	saveConfig(&config)

	fmt.Println("Add success!")
	return nil
}

func listItem() {
	config, err := readConfig()
	if err != nil {
		log.Fatal("Read config failed", err)
	}
	idx := 1
	for k := range config.Items {
		fmt.Printf("%d. %s\n", idx, k)
		idx++
	}
}

func deleteItem(name string) {
	config, err := readConfig()
	if err != nil {
		log.Fatal("Read config failed", err)
	}
	delete(config.Items, name)
	saveConfig(&config)

	fmt.Println("Delete success!")
}

func getCode() {
	config, err := readConfig()
	if err != nil {
		log.Fatal("Read config failed, run 'tfat help' for help", err)
	}
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
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter index: ")
		text, _ := reader.ReadString('\n')
		idx, err = strconv.Atoi(strings.TrimSpace(text))
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
		if err != nil {
			log.Fatal("Get code ERROR:", err)
		}
		secondsRemaining := 30 - (time.Now().Unix() % 30)
		fmt.Printf("%06d (expires in %ds) \r", pwd, secondsRemaining)
		if lastCode != pwd {
			lastCode = pwd
			clipboard.WriteAll(string(pwd))
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
			Name:      "modify",
			Aliases:   []string{"m"},
			UsageText: "tfat modify <NAME> <KEY>",
			Usage:     "Modify an item's key",
			Action: func(c *cli.Context) error {
				if len(c.Args()) < 2 {
					log.Fatal("Invalid arguments, see 'go help modify'")
				}
				item := c.Args().First()
				secret := c.Args()[1]
				addOrModifyItem(item, secret)
				return nil
			},
		},
		{
			Name:      "delete",
			Aliases:   []string{"d"},
			UsageText: "tfat delete <NAME>",
			Usage:     "Delete an item",
			Action: func(c *cli.Context) error {
				if len(c.Args()) < 1 {
					log.Fatal("Invalid arguments, see 'go help delete'")
				}
				deleteItem(c.Args().First())
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
