// Command chatbot-go is a chat-xdk example bot.
//
// Flow (encrypt on send, decrypt on receive): load keys -> batch-decrypt the backlog ->
// poll for new events -> decrypt each -> reply -> encrypt + sign -> send.
//
// Configure via environment variables (see .env.example) and run:
//
//	go run .
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// loadDotenv is a tiny .env loader so the example has no extra dependencies.
func loadDotenv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		if _, ok := os.LookupEnv(strings.TrimSpace(k)); !ok {
			os.Setenv(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
}

func main() {
	loadDotenv(".env")

	accessToken := os.Getenv("X_ACCESS_TOKEN")
	conversationID := os.Getenv("CHAT_CONVERSATION_ID")
	privateKeysB64 := os.Getenv("CHAT_PRIVATE_KEYS_B64")
	signingKeyVersion := os.Getenv("CHAT_SIGNING_KEY_VERSION")
	if signingKeyVersion == "" {
		signingKeyVersion = "1"
	}

	core := NewChatCore()
	defer core.Close()

	if privateKeysB64 == "" {
		// First run: generate keys, print registration payload + private blob.
		payload, priv, err := core.GenerateAndRegister()
		if err != nil {
			log.Fatalf("generate_keypairs: %v", err)
		}
		reg, _ := json.MarshalIndent(payload.PublicKey, "", "  ")
		fmt.Println("No CHAT_PRIVATE_KEYS_B64 set — generated a new identity.")
		fmt.Println("\n1) Register this public key with the X API (one-time provisioning):")
		fmt.Println(string(reg))
		fmt.Println("\n2) Save the private key in your .env so the bot reuses the identity:")
		fmt.Printf("CHAT_PRIVATE_KEYS_B64=%s\n", priv)
		fmt.Println("\nThen re-run.")
		return
	}

	if err := core.LoadKeys(privateKeysB64, signingKeyVersion); err != nil {
		log.Fatalf("load_keys: %v", err)
	}

	if accessToken == "" || conversationID == "" {
		fmt.Println("Set X_ACCESS_TOKEN and CHAT_CONVERSATION_ID in .env to run the bot.")
		return
	}

	api := NewXChatClient(accessToken, os.Getenv("X_API_BASE_URL"))
	botUserID := os.Getenv("CHAT_BOT_USER_ID")
	if botUserID == "" {
		id, err := api.GetMyUserID()
		if err != nil {
			log.Fatalf("get_my_user_id: %v", err)
		}
		botUserID = id
	}

	bot := NewBot(core, api, botUserID)
	if err := bot.Run(conversationID, 3*time.Second); err != nil {
		log.Fatalf("run: %v", err)
	}
}
