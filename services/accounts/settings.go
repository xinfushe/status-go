package accounts

import (
	"context"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"

	"github.com/status-im/status-go/multiaccounts/accounts"
	"github.com/status-im/status-go/params"
)

func NewSettingsAPI(db *accounts.Database) *SettingsAPI {
	return &SettingsAPI{db}
}

// SettingsAPI is class with methods available over RPC.
type SettingsAPI struct {
	db *accounts.Database
}

func (api *SettingsAPI) SaveConfig(ctx context.Context, addr common.Address, conf map[string]interface{}) error {
	return api.db.SaveConfig(addr, conf)
}

func (api *SettingsAPI) GetConfig(ctx context.Context, addr common.Address, typ string) (json.RawMessage, error) {
	return api.db.GetConfigBlob(addr, typ)
}

func (api *SettingsAPI) GetConfigs(ctx context.Context, addr common.Address, types []string) (map[string]json.RawMessage, error) {
	return api.db.GetConfigBlobs(addr, types)
}

func (api *SettingsAPI) SaveNodeConfig(ctx context.Context, addr common.Address, nc *params.NodeConfig) error {
	conf := map[string]interface{}{accounts.NodeConfigTag: nc}
	return api.db.SaveConfig(addr, conf)
}
