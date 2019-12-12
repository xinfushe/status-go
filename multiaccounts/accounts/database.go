package accounts

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/status-im/status-go/sqlite"
)

const (
	uniqueChatConstraint   = "UNIQUE constraint failed: accounts.chat"
	uniqueWalletConstraint = "UNIQUE constraint failed: accounts.wallet"
)

var (
	settingsFields = map[string]bool{
		"chaos_mode":                true,
		"config":                    true,
		"currency":                  true,
		"custom_bootnodes":          true,
		"custom_bootnodes_enabled":  true,
		"dapps_address":             true,
		"datasync":                  true,
		"dev_mode":                  true,
		"eip1581_address":           true,
		"fleet":                     true,
		"hide_home_tooltip":         true,
		"installation_id":           true,
		"key_uid":                   true,
		"keycard_instance_uid":      true,
		"keycard_paired_on":         true,
		"keycard_pairing":           true,
		"last_updated":              true,
		"latest_derived_path":       true,
		"log_level":                 true,
		"mnemonic":                  true,
		"name":                      true,
		"notification_enabled":      true,
		"photo_path":                true,
		"pinned_mailserver":         true,
		"preferred_name":            true,
		"preview_privacy":           true,
		"public_key":                true,
		"remember_syncing_choice":   true,
		"show_name":                 true,
		"stickers_packs_installed":  true,
		"stickers_recent_stickers":  true,
		"syncing_on_mobile_network": true,
		"usernames":                 true,
		"wallet_root_address":       true,
		"wallet_set_up_passed":      true,
		"wallet_visible_tokens":     true,
	}

	// ErrWalletNotUnique returned if another account has `wallet` field set to true.
	ErrWalletNotUnique = errors.New("another account is set to be default wallet. disable it before using new")
	// ErrChatNotUnique returned if another account has `chat` field set to true.
	ErrChatNotUnique = errors.New("another account is set to be default chat. disable it before using new")
	// ErrInvalidConfig returned if config isn't allowed
	ErrInvalidConfig = errors.New("configuration value not allowed")
)

type Account struct {
	Address   common.Address `json:"address"`
	Wallet    bool           `json:"wallet"`
	Chat      bool           `json:"chat"`
	Type      string         `json:"type,omitempty"`
	Storage   string         `json:"storage,omitempty"`
	Path      string         `json:"path,omitempty"`
	PublicKey hexutil.Bytes  `json:"public-key,omitempty"`
	Name      string         `json:"name"`
	Color     string         `json:"color"`
}

type configMap map[string]interface{}

func NewDB(db *sql.DB) *Database {
	return &Database{db: db}
}

// Database sql wrapper for operations with browser objects.
type Database struct {
	db *sql.DB
}

// Close closes database.
func (db Database) Close() error {
	return db.db.Close()
}

func (db *Database) SaveConfig(addr common.Address, conf configMap) error {
	if len(conf) == 0 {
		return nil
	}

	var (
		vals = []interface{}{addr}
		cols = []string{"address"}
	)
	for typ, val := range conf {
		if _, ok := settingsFields[typ]; !ok {
			return ErrInvalidConfig
		}

		cols = append(cols, typ)
		vals = append(vals, &sqlite.JSONBlob{Data: val})
	}

	// Try to insert first, if not we update.
	stmt := fmt.Sprintf("INSERT INTO settings (%s) VALUES (?%s)",
		strings.Join(cols, ", "),
		strings.Repeat(", ?", len(vals)-1),
	)

	_, err := db.db.Exec(stmt, vals...)
	if err != nil {
		stmt := fmt.Sprintf("UPDATE settings SET %s = ? WHERE address = ?", strings.Join(cols[1:], " = ?, "))
		_, err := db.db.Exec(stmt, append(vals[1:], addr)...)
		return err
	}

	return nil
}

func (db *Database) GetConfig(addr common.Address, typ string, value interface{}) error {
	if _, ok := settingsFields[typ]; !ok {
		return ErrInvalidConfig
	}

	stmt := fmt.Sprintf("SELECT %s FROM settings WHERE address = ?", typ)
	return db.db.QueryRow(stmt, addr).Scan(&sqlite.JSONBlob{Data: value})
}

func (db *Database) GetConfigBlob(addr common.Address, typ string) (json.RawMessage, error) {
	cfgs, err := db.GetConfigBlobs(addr, []string{typ})
	return cfgs[typ], err
}

func (db *Database) GetConfigBlobs(addr common.Address, types []string) (map[string]json.RawMessage, error) {
	for _, typ := range types {
		if _, ok := settingsFields[typ]; !ok {
			return nil, ErrInvalidConfig
		}
	}

	var (
		settings = map[string]json.RawMessage{}
		stmt     = fmt.Sprintf("SELECT %s FROM settings WHERE address = ?", strings.Join(types, ", "))

		ptrs = make([]interface{}, len(types))
		vals = make([]json.RawMessage, len(types))
	)
	for i, _ := range types {
		ptrs[i] = &vals[i]
	}
	if err := db.db.QueryRow(stmt, addr).Scan(ptrs...); err != nil {
		return nil, err
	}

	for i, typ := range types {
		settings[typ] = vals[i]
	}

	return settings, nil
}

func (db *Database) GetAccounts() ([]Account, error) {
	rows, err := db.db.Query("SELECT address, wallet, chat, type, storage, pubkey, path, name, color FROM accounts ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	accounts := []Account{}
	pubkey := []byte{}
	for rows.Next() {
		acc := Account{}
		err := rows.Scan(
			&acc.Address, &acc.Wallet, &acc.Chat, &acc.Type, &acc.Storage,
			&pubkey, &acc.Path, &acc.Name, &acc.Color)
		if err != nil {
			return nil, err
		}
		if lth := len(pubkey); lth > 0 {
			acc.PublicKey = make(hexutil.Bytes, lth)
			copy(acc.PublicKey, pubkey)
		}
		accounts = append(accounts, acc)
	}
	return accounts, nil
}

func (db *Database) SaveAccounts(accounts []Account) (err error) {
	var (
		tx     *sql.Tx
		insert *sql.Stmt
		update *sql.Stmt
	)
	tx, err = db.db.Begin()
	if err != nil {
		return
	}
	defer func() {
		if err == nil {
			err = tx.Commit()
			return
		}
		_ = tx.Rollback()
	}()
	// NOTE(dshulyak) replace all record values using address (primary key)
	// can't use `insert or replace` because of the additional constraints (wallet and chat)
	insert, err = tx.Prepare("INSERT OR IGNORE INTO accounts (address, created_at, updated_at) VALUES (?, datetime('now'), datetime('now'))")
	if err != nil {
		return err
	}
	update, err = tx.Prepare("UPDATE accounts SET wallet = ?, chat = ?, type = ?, storage = ?, pubkey = ?, path = ?, name = ?, color = ?, updated_at = datetime('now') WHERE address = ?")
	if err != nil {
		return err
	}
	for i := range accounts {
		acc := &accounts[i]
		_, err = insert.Exec(acc.Address)
		if err != nil {
			return
		}
		_, err = update.Exec(acc.Wallet, acc.Chat, acc.Type, acc.Storage, acc.PublicKey, acc.Path, acc.Name, acc.Color, acc.Address)
		if err != nil {
			switch err.Error() {
			case uniqueChatConstraint:
				err = ErrChatNotUnique
			case uniqueWalletConstraint:
				err = ErrWalletNotUnique
			}
			return
		}
	}
	return
}

func (db *Database) DeleteAccount(address common.Address) error {
	_, err := db.db.Exec("DELETE FROM accounts WHERE address = ?", address)
	return err
}

func (db *Database) GetWalletAddress() (rst common.Address, err error) {
	err = db.db.QueryRow("SELECT address FROM accounts WHERE wallet = 1").Scan(&rst)
	return
}

func (db *Database) GetChatAddress() (rst common.Address, err error) {
	err = db.db.QueryRow("SELECT address FROM accounts WHERE chat = 1").Scan(&rst)
	return
}

func (db *Database) GetAddresses() (rst []common.Address, err error) {
	rows, err := db.db.Query("SELECT address FROM accounts ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		addr := common.Address{}
		err = rows.Scan(&addr)
		if err != nil {
			return nil, err
		}
		rst = append(rst, addr)
	}
	return rst, nil
}

// AddressExists returns true if given address is stored in database.
func (db *Database) AddressExists(address common.Address) (exists bool, err error) {
	err = db.db.QueryRow("SELECT EXISTS (SELECT 1 FROM accounts WHERE address = ?)", address).Scan(&exists)
	return exists, err
}
