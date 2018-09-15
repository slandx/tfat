# tfat
Two factor authentication(2FA) command line tool

## features
- save config file with AES encrypt
- save by password
- multi items
- auto refresh code per seconds
- copy to clipboard if there is a new code

## usage

### get code
- auto refresh per seconds
- copy to clipboard if there is a new code
```bash
tfat
# output:
# 602887 (expires in 5s)
```
if there are many items in config, it will list all of them, and let you choose one to get code
```bash
tfat
# output:
# 1. one
# 2. two
# 3. three
# Enter index: 1
# 698030 (expires in 16s)
```

### list all items
```bash
tfat list
```

### add an item
```bash
tfat add <NAME> <SECRET>
```

### delete an item
```bash
tfat delete <NAME>
```

### help
```bash
$ tfat.exe help
NAME:
   Two Factor Authentication(2FA) Tool - Help to generate 2FA code

USAGE:
   tfat.exe [global options] command [command options] [arguments...]

VERSION:
   0.0.1

COMMANDS:
     list       List all items
     add        Add a new item
     delete, d  Delete an item
     help, h    Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     Show this help
   --version, -v  Print version
```
