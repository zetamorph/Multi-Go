package main

/*
Copyright 2018 TheRedSpy15

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/akamensky/argparse"
	"github.com/daviddengcn/go-colortext"
)

func main() {
	parser := argparse.NewParser("SecureMultiTool", "Runs multiple security orientated tasks")

	// TODO: use native go flags
	// Create flags
	t := parser.String("t", "Task", &argparse.Options{Required: true, Help: "Task to run"})
	r := parser.String("r", "Target", &argparse.Options{Required: false, Help: "Target to run task on"})

	// Error handling
	err := parser.Parse(os.Args)
	if err != nil {
		panic(parser.Usage(err))
	}

	// TODO: add 'bleach'
	// Determine task
	switch *t {
	case "Hash":
		println("Running task:", *t, "\nTarget:", *r)
		hashFile(*r)
	case "pwnAccount":
		println("Running task:", *t, "\nTarget:", *r)
		pwnAccount(*r)
	case "encryptFile":
		println("Running task:", *t, "\nTarget:", *r)
		encryptFileTask(*r)
	case "decryptFile":
		println("Running task:", *t, "\nTarget:", *r)
		decryptFileTask(*r)
	case "About":
		about()
	case "List":
		listTasks()
	case "Scrape":
		println("Running task:", *t, "\nTarget:", *r)
		scrape(*r)
	default:
		ct.Foreground(ct.Red, true)
		println("Invalid task - ", *t)
		ct.Foreground(ct.Yellow, false)
		println("Use '--help' or '-t List'")
	}
}

// TODO: document
// Takes a file path, and then prints the hash of the file
func hashFile(target string) {
	file := readFileIntoByte(target)
	hash := sha1.New()
	hash.Write(file)
	target = base64.URLEncoding.EncodeToString(hash.Sum(nil))

	fmt.Println("SHA-1 hash :", target)
}

// ListTasks - lists all currently working tasks
func listTasks() {
	ct.Foreground(ct.Yellow, false)
	println("Available tasks:")
	println("Hash -r [file path]")
	println("encryptFile -r [file path]")
	println("decryptFile -r [file path]")
	println("Scape - [URL]")
	println("About") // keep at bottom of print statements
}

// TODO: use pwn api to see if an account has been pwned
func pwnAccount(target string) {
	ct.Foreground(ct.Red, true)
	println("Not a working feature yet")
}

// Encrypts the target file
func encryptFileTask(target string) {
	data := readFileIntoByte(target)
	password := getPassword()
	encryptFile(target, data, password)
	println("\nFile encrypted!")
}

// BUG: decrypted file is unusable
// Decrypts the target file
func decryptFileTask(target string) {
	password := getPassword()
	decryptFile(target, password)
	println("\nFile decrypted!")
}

// TODO: description about program
// Prints details about the program
func about() {
	printBanner()
	println("Multi Go - 1.0.0", "\nBy - TheRedSpy15")
	println("GitHub:", "https://github.com/TheRedSpy15")
}

// NOTE: refer to 'scrape' function
// Scrapes target website
func scapeTask(target string) {
	checkTarget(target)
	scrape(target)
}
