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
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/smtp"
	"os"

	"github.com/daviddengcn/go-colortext"
	"github.com/jordan-wright/email"
)

// TODO: document
// Takes a file path, and then prints the hash of the file
func hashFile(target string) {
	checkTarget(target)
	file := readFileIntoByte(target)
	hash := sha1.New() // create sh1 object
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
	println("Scrape - [URL]")
	println("About") // keep at bottom of print statements
}

// TODO: use pwn api to see if an account has been pwned
func pwnAccount(target string) {
	ct.Foreground(ct.Red, true)
	println("Not a working feature yet")
}

// Encrypts the target file
func encryptFileTask(target string) {
	checkTarget(target)
	data := readFileIntoByte(target)
	password := getPassword()
	encryptFile(target, data, password)
	println("\nFile encrypted!")
}

// BUG: decrypted file is unusable
// Decrypts the target file
func decryptFileTask(target string) {
	checkTarget(target)
	password := getPassword()
	decryptFile(target, password)
	println("\nFile decrypted!")
}

// Prints details about the program
func about() {
	printBanner()
	println("Multi Go - 1.0.0", "\nBy - TheRedSpy15")
	println("GitHub:", "https://github.com/TheRedSpy15")
	println("Project Page:", "https://github.com/TheRedSpy15/Multi-Go")
	println("\nMulti Go allows IT admins and Cyber Security experts")
	println("to conveniently perform all sorts of tasks.")
}

// Scrapes target website
func scapeTask(target string) {
	checkTarget(target)
	scrape(target)
}

// TODO: send file option
// TODO: break up into multiple functions
// Send email
func emailTask() {
	reader := bufio.NewReader(os.Stdin) // make reader object
	e := email.NewEmail()
	ct.Foreground(ct.Yellow, false)
	println("Prepare email")
	ct.ResetColor()

	// email setup
	print("From: ")
	e.From, _ = reader.ReadString('\n')

	print("To: ")
	to, _ := reader.ReadString('\n')
	e.To = []string{to}

	print("Bcc (leave blank if none): ")
	Bcc, _ := reader.ReadString('\n')
	e.Bcc = []string{Bcc}

	print("Cc (leave blank if none): ")
	Cc, _ := reader.ReadString('\n')
	e.To = []string{Cc}

	print("Subject: ")
	e.Subject, _ = reader.ReadString('\n')

	print("Text: ")
	Text, _ := reader.ReadString('\n')
	e.To = []string{Text}

	// authentication
	print("Provider (example: smtp.gmail.com): ")
	provider, _ := reader.ReadString('\n')
	print("Port (example: 587): ")
	port, _ := reader.ReadString('\n')
	print("Password (leave blank if none): ")
	password, _ := reader.ReadString('\n')

	// confirmation
	print("Confirm send? (yes/no): ")
	confirm, _ := reader.ReadString('\n')
	if confirm == "yes" {
		// sending
		err := e.Send(provider+port, smtp.PlainAuth("", e.From, password, provider))
		if err != nil {
			ct.Foreground(ct.Red, true)
			println("error sending email -", err.Error())
		}
	} else {
		ct.Foreground(ct.Red, true)
		println("Cancelled!")
	}
}
