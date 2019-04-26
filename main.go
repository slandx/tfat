package main

import (
	"fmt"
	"os"
	"time"

	"sort"
	"strings"

	"encoding/base32"
	"strconv"

	"github.com/atotto/clipboard"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var errNoAccountFound = errors.New("no account exists")
var errInvalidOption = errors.New("invalid option, check 'tfat help'")
var errInvalidBase32 = errors.New("the key is not a valid base32 encoding")

var runInLoop bool

func checkResult(err error, errMsg string) {
	if err != nil {
		fmt.Println(errMsg + ": " + err.Error())
		os.Exit(1)
	}
}

func addOrModifyAccount(name, secret string) error {
	if len(name) == 0 || len(secret) == 0 {
		checkResult(errInvalidOption, "Error")
	}

	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		checkResult(errInvalidBase32, "Error")
	}

	config, err := readConfig()
	checkResult(err, "Open data failed")
	if config.IsNew {
		err = initPassword(&config)
		checkResult(err, "Failed to add account")
	}
	config.Accounts[name] = strings.ToUpper(secret)

	saveConfig(&config)

	fmt.Printf("Add %s successfully!\n", name)
	return nil
}

func deleteAccount(name string) {
	config, err := readConfig()
	checkResult(err, "Open data failed")
	if _, ok := config.Accounts[name]; ok {
		delete(config.Accounts, name)
		err = saveConfig(&config)
		checkResult(err, "Failed to delete account")
		fmt.Println("Delete success!")
	} else {
		fmt.Printf("Account %s is not found", name)
	}
}

func changePassword() {
	config, err := readConfig()
	checkResult(err, "Open data failed")
	err = initPassword(&config)
	checkResult(err, "Failed to change password")
	saveConfig(&config)
	fmt.Println("Change password successfully!")
}

func getCode() {
	config, err := readConfig()
	checkResult(err, "Open data failed")

	var names []string
	idx := 1
	for k := range config.Accounts {
		names = append(names, k)
		fmt.Printf("%d. %s\n", idx, k)
		idx++
	}
	if len(names) <= 0 {
		checkResult(errNoAccountFound, "Failed to get code")
	} else if len(names) > 1 {
		for true {
			idx, err = strconv.Atoi(getUserInput("select", false))
			if err == nil && idx >= 1 && idx <= len(names) {
				break
			}
			fmt.Printf("Number should be in 1..%d\n", len(names))
		}
	} else {
		idx = 1
	}
	keyStr := config.Accounts[names[idx-1]]

	var lastCode uint32
	for true {
		pwd, err := OneTimePassword(keyStr)
		checkResult(err, "Failed to get code")

		secondsRemaining := 30 - (time.Now().Unix() % 30)
		fmt.Printf("\r%06d (remain %ds) ", pwd, secondsRemaining)
		if lastCode != pwd {
			lastCode = pwd
			clipboard.WriteAll(fmt.Sprintf("%06d", pwd))
		}
		if !runInLoop {
			fmt.Println("")
			break
		}
		time.Sleep(1 * time.Second)
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "Two Factor Authentication(2FA) Tool"
	app.Usage = "Help to generate 2FA code"
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:        "loop, l",
			Usage:       "generate code in loop",
			Destination: &runInLoop,
		},
	}
	app.Commands = []cli.Command{
		{
			Name:      "add",
			UsageText: "tfat add <NAME> <KEY>",
			Usage:     "Add a new account",
			Action: func(c *cli.Context) error {
				if len(c.Args()) < 2 {
					checkResult(errInvalidOption, "Error")
				}
				account := c.Args().First()
				secret := c.Args()[1]
				addOrModifyAccount(account, secret)
				return nil
			},
		},
		{
			Name:      "delete",
			UsageText: "tfat delete <NAME>",
			Usage:     "Delete an account",
			Action: func(c *cli.Context) error {
				if len(c.Args()) < 1 {
					checkResult(errInvalidOption, "Error")
				}
				deleteAccount(c.Args().First())
				return nil
			},
		}, {
			Name:      "password",
			UsageText: "tfat password <PASSWORD>",
			Usage:     "Change password",
			Action: func(c *cli.Context) error {
				changePassword()
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
		checkResult(err, "Error")
	}
}
