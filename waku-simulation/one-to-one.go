package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/codeskyblue/go-sh"
)

const (
	StatusgoBinary = "../build/bin/statusd"

	Config = `
{
	"DataDir": "%s",
	"WakuConfig": {
		"Enabled": true
	},
	"IPCEnabled": true,
	"ListenAddr": "%s"
}
`

	BobConfigFile = "./bob-config.json"
	BobDataDir    = "./bob-data"
	BobLogFile    = "./bob.log"
	BobListenAddr = "127.0.0.1:30353"

	AliceConfigFile = "./alice-config.json"
	AliceDataDir    = "./alice-data"
	AliceLogFile    = "./alice.log"
	AliceListenAddr = "127.0.0.1:30363"
)

func main() {
	var (
		bobSess, aliceSess *sh.Session
		err                error
	)

	defer func() {
		if bobSess != nil {
			bobSess.Kill(os.Interrupt)
		}
		if aliceSess != nil {
			aliceSess.Kill(os.Interrupt)
		}

		if err != nil {
			log.Fatal(err)
		}

		if err := cleanup(BobDataDir, BobConfigFile, BobLogFile); err != nil {
			log.Fatalf("failed to clean up Bob's files: %v", err)
		}
		if err := cleanup(AliceDataDir, AliceConfigFile, AliceLogFile); err != nil {
			log.Fatalf("failed to clean up Alice's files: %v", err)
		}
	}()

	if err := createConfig(BobConfigFile, BobDataDir, BobListenAddr); err != nil {
		log.Fatalf("failed to create a config file: %v", err)
	}

	if err := createConfig(AliceConfigFile, AliceDataDir, AliceListenAddr); err != nil {
		log.Fatalf("failed to create a config file: %v", err)
	}

	bobSess = sh.Command(StatusgoBinary, "-c", BobConfigFile)
	go func() {
		f, err := os.OpenFile(BobLogFile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("failed to create Bob's log file: %v", err)
		}
		bobSess.Stdout = f
		bobSess.Stderr = f

		if err := bobSess.Start(); err != nil {
			log.Fatalf("failed to start Bob's node: %v", err)
		}
	}()

	aliceSess = sh.Command(StatusgoBinary, "-c", AliceConfigFile)
	go func() {
		f, err := os.OpenFile(AliceLogFile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("failed to create Bob's log file: %v", err)
		}
		aliceSess.Stdout = f
		aliceSess.Stderr = f

		if err := aliceSess.Start(); err != nil {
			log.Fatalf("failed to start Alice's node: %v", err)
		}
	}()

	time.Sleep(time.Second)

	aliceEnode, err := getEnode(AliceDataDir)
	if err != nil {
		err = fmt.Errorf("failed to get Alice's enode address: %v", err)
		return
	}
	log.Printf("alice enode address: %s", aliceEnode)

	if err := addPeer(BobDataDir, aliceEnode); err != nil {
		err = fmt.Errorf("failed to add Alice as a peer: %v", err)
		return
	}

	err = eventually(func() error {
		res, err := hasPeer(BobDataDir, aliceEnode)
		if err != nil {
			return err
		}
		if !res {
			return errors.New("peer not found")
		}
		return nil
	}, 3, time.Second*5)
	if err != nil {
		err = fmt.Errorf("Alice's peer not found: %v", err)
		return
	}

	aliceMessageFilter, err := newMessageFilter(AliceDataDir)
	if err != nil {
		err = fmt.Errorf("failed to create Alice's message filter: %v", err)
		return
	}
	log.Printf("created message filter: %s", aliceMessageFilter)

	hash, err := sendMessage(BobDataDir)
	if err != nil {
		err = fmt.Errorf("failed to send message to Alice: %v", err)
		return
	}
	log.Printf("send a message with hash %s", hash)

	err = eventually(func() error {
		exists, err := receiveMessage(AliceDataDir, aliceMessageFilter, hash)
		if err != nil {
			return err
		}
		if !exists {
			return errors.New("message not found")
		}
		return nil
	}, 3, time.Second*5)
	if err != nil {
		err = fmt.Errorf("failed to receive messages by Alice: %v", err)
		return
	}
}

func createConfig(path string, cfgArgs ...interface{}) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open Bob's config file: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(fmt.Sprintf(Config, cfgArgs...)); err != nil {
		return fmt.Errorf("failed to write Bob's config file: %w", err)
	}
	return nil
}

func getEnode(dataDir string) (string, error) {
	out, err := sh.
		Command("echo", `{"jsonrpc":"2.0","method":"admin_nodeInfo","params":[],"id":1}`).
		Command("nc", "-U", filepath.Join(dataDir, "geth.ipc")).
		Output()
	if err != nil {
		return "", err
	}

	type nodeInfo struct {
		Enode string `json:"enode"`
		IP    string `json:"ip"`
	}
	type result struct {
		Result nodeInfo `json:"result"`
	}

	var res result
	if err := json.Unmarshal(out, &res); err != nil {
		return "", err
	}

	return strings.Replace(res.Result.Enode, res.Result.IP, "127.0.0.1", 1), nil
}

func addPeer(dataDir string, enode string) error {
	return sh.
		Command("echo", fmt.Sprintf(`{"jsonrpc":"2.0","method":"admin_addPeer","params":["%s"],"id":1}`, enode)).
		Command("nc", "-U", filepath.Join(dataDir, "geth.ipc")).
		Run()
}

func hasPeer(dataDir string, enode string) (bool, error) {
	out, err := sh.
		Command("echo", `{"jsonrpc":"2.0","method":"admin_peers","params":[],"id":1}`).
		Command("nc", "-U", filepath.Join(dataDir, "geth.ipc")).
		Output()
	if err != nil {
		return false, err
	}

	type peerInfo struct {
		Enode string `json:"enode"`
	}
	type result struct {
		Result []peerInfo `json:"result"`
	}

	var res result
	if err := json.Unmarshal(out, &res); err != nil {
		return false, err
	}

	for _, item := range res.Result {
		if item.Enode == enode {
			return true, nil
		}
	}
	return false, nil
}

func newMessageFilter(dataDir string) (string, error) {
	out, err := sh.
		Command("echo", `{"jsonrpc":"2.0","method":"waku_generateSymKeyFromPassword","params":["secret"],"id":1}`).
		Command("nc", "-U", filepath.Join(dataDir, "geth.ipc")).
		Output()
	if err != nil {
		return "", err
	}

	type result struct {
		Result string    `json:"result"`
		Error  *rpcError `json:"error"`
	}

	var symKeyRes result
	if err := json.Unmarshal(out, &symKeyRes); err != nil {
		return "", err
	} else if symKeyRes.Error != nil {
		return "", fmt.Errorf(symKeyRes.Error.Message)
	}

	criteria := fmt.Sprintf(`{"symKeyID": "%s", "topics": ["0xaabbccdd"]}`, symKeyRes.Result)
	out, err = sh.
		Command("echo", fmt.Sprintf(`{"jsonrpc":"2.0","method":"waku_newMessageFilter","params":[%s],"id":1}`, criteria)).
		Command("nc", "-U", filepath.Join(dataDir, "geth.ipc")).
		Output()
	if err != nil {
		return "", err
	}

	var messageFilterRes result
	if err := json.Unmarshal(out, &messageFilterRes); err != nil {
		return "", err
	} else if messageFilterRes.Error != nil {
		return "", fmt.Errorf(messageFilterRes.Error.Message)
	}
	return messageFilterRes.Result, nil
}

func sendMessage(dataDir string) (string, error) {
	out, err := sh.
		Command("echo", `{"jsonrpc":"2.0","method":"waku_generateSymKeyFromPassword","params":["secret"],"id":1}`).
		Command("nc", "-U", filepath.Join(dataDir, "geth.ipc")).
		Output()
	if err != nil {
		return "", err
	}

	type result struct {
		Result string    `json:"result"`
		Error  *rpcError `json:"error"`
	}

	var symKeyRes result
	if err := json.Unmarshal(out, &symKeyRes); err != nil {
		return "", err
	} else if symKeyRes.Error != nil {
		return "", fmt.Errorf(symKeyRes.Error.Message)
	}

	messageParams := fmt.Sprintf(
		`{"symKeyID": "%s", "ttl": 10, "topic": "0xaabbccdd", "powTarget": 2.0, "powTime": 5, "payload": "0x010203"}`,
		symKeyRes.Result,
	)
	out, err = sh.
		Command("echo", fmt.Sprintf(`{"jsonrpc":"2.0","method":"waku_post","params":[%s],"id":1}`, messageParams)).
		Command("nc", "-U", filepath.Join(dataDir, "geth.ipc")).
		Output()
	if err != nil {
		return "", err
	}

	var hashRes result
	if err := json.Unmarshal(out, &hashRes); err != nil {
		return "", err
	} else if hashRes.Error != nil {
		return "", fmt.Errorf(hashRes.Error.Message)
	}
	return hashRes.Result, nil
}

func receiveMessage(dataDir, filterID, hash string) (bool, error) {
	out, err := sh.
		Command("echo", fmt.Sprintf(`{"jsonrpc":"2.0","method":"waku_getFilterMessages","params":["%s"],"id":1}`, filterID)).
		Command("nc", "-U", filepath.Join(dataDir, "geth.ipc")).
		Output()
	if err != nil {
		return false, err
	}

	type message struct {
		Hash []byte `json:"hash"` // TODO: apparently strings prefixed with 0x are treated as bytes by JSON marshaler
	}
	type result struct {
		Result []message `json:"result"`
		Error  *rpcError `json:"error"`
	}

	var messages result
	if err := json.Unmarshal(out, &messages); err != nil {
		return false, err
	} else if messages.Error != nil {
		return false, fmt.Errorf(messages.Error.Message)
	} else {
		log.Printf("received messages: %+v", messages.Result)
	}

	for _, m := range messages.Result {
		if "0x"+hex.EncodeToString(m.Hash) == hash {
			return true, nil
		}
	}
	return false, nil
}

func eventually(f func() error, retries int, timeout time.Duration) error {
	errC := make(chan error, 1)

	go func() {
		var err error
		for i := 0; i < retries; i++ {
			err = f()
			if err == nil {
				break
			}
			time.Sleep(time.Second)
		}
		errC <- err
	}()

	select {
	case <-time.After(timeout):
		return errors.New("timeout")
	case err := <-errC:
		return err
	}
}

func cleanup(filePaths ...string) error {
	for _, path := range filePaths {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

type rpcError struct {
	Message string `json:"message"`
}
