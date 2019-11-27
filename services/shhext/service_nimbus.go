// +build nimbus

package shhext

import (
	"crypto/ecdsa"
	"database/sql"
	"os"
	"path/filepath"
	"time"

	"github.com/status-im/status-go/logutils"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/status-im/status-go/db"
	"github.com/status-im/status-go/params"
	"github.com/status-im/status-go/signal"

	"github.com/syndtr/goleveldb/leveldb"
	"go.uber.org/zap"

	"github.com/status-im/status-go/eth-node/types"
	protocol "github.com/status-im/status-go/protocol"
	protocolwhisper "github.com/status-im/status-go/protocol/transport/whisper"
)

const (
	// defaultConnectionsTarget used in Service.Start if configured connection target is 0.
	defaultConnectionsTarget = 1
	// defaultTimeoutWaitAdded is a timeout to use to establish initial connections.
	defaultTimeoutWaitAdded = 5 * time.Second
)

// EnvelopeEventsHandler used for two different event types.
type EnvelopeEventsHandler interface {
	EnvelopeSent([][]byte)
	EnvelopeExpired([][]byte, error)
	MailServerRequestCompleted(types.Hash, types.Hash, []byte, error)
	MailServerRequestExpired(types.Hash)
}

// Service is a service that provides some additional Whisper API.
type Service struct {
	messenger       *protocol.Messenger
	identity        *ecdsa.PrivateKey
	cancelMessenger chan struct{}

	storage db.TransactionalStorage
	n       types.Node
	w       types.Whisper
	config  params.ShhextConfig
	//server           *p2p.Server
	nodeID *ecdsa.PrivateKey
}

// New returns a new shhext Service.
func New(n types.Node, ctx interface{}, ldb *leveldb.DB, config params.ShhextConfig) *Service {
	w, err := n.GetWhisper(ctx)
	if err != nil {
		panic(err)
	}
	return &Service{
		storage: db.NewLevelDBStorage(ldb),
		n:       n,
		w:       w,
		config:  config,
	}
}

func (s *Service) InitProtocol(identity *ecdsa.PrivateKey, db *sql.DB) error { // nolint: gocyclo
	if !s.config.PFSEnabled {
		return nil
	}

	s.identity = identity

	dataDir := filepath.Clean(s.config.BackupDisabledDataDir)

	if err := os.MkdirAll(dataDir, os.ModePerm); err != nil {
		return err
	}

	// Create a custom zap.Logger which will forward logs from status-go/protocol to status-go logger.
	zapLogger, err := logutils.NewZapLoggerWithAdapter(logutils.Logger())
	if err != nil {
		return err
	}

	// envelopesMonitorConfig := &protocolwhisper.EnvelopesMonitorConfig{
	// 	MaxAttempts:                    s.config.MaxMessageDeliveryAttempts,
	// 	MailserverConfirmationsEnabled: s.config.MailServerConfirmations,
	// 	IsMailserver: func(peer types.EnodeID) bool {
	// 		return s.peerStore.Exist(peer)
	// 	},
	// 	EnvelopeEventsHandler: EnvelopeSignalHandler{},
	// 	Logger:                zapLogger,
	// }
	options := buildMessengerOptions(s.config, db, nil, zapLogger)

	messenger, err := protocol.NewMessenger(
		identity,
		s.n,
		s.config.InstallationID,
		options...,
	)
	if err != nil {
		return err
	}
	s.messenger = messenger
	// Start a loop that retrieves all messages and propagates them to status-react.
	s.cancelMessenger = make(chan struct{})
	go s.retrieveMessagesLoop(time.Second, s.cancelMessenger)

	return s.messenger.Init()
}

func (s *Service) retrieveMessagesLoop(tick time.Duration, cancel <-chan struct{}) {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			response, err := s.messenger.RetrieveAll()
			if err != nil {
				log.Error("failed to retrieve raw messages", "err", err)
				continue
			}
			if !response.IsEmpty() {
				PublisherSignalHandler{}.NewMessages(response)
			}
		case <-cancel:
			return
		}
	}
}

func (s *Service) ConfirmMessagesProcessed(messageIDs [][]byte) error {
	return s.messenger.ConfirmMessagesProcessed(messageIDs)
}

func (s *Service) EnableInstallation(installationID string) error {
	return s.messenger.EnableInstallation(installationID)
}

// DisableInstallation disables an installation for multi-device sync.
func (s *Service) DisableInstallation(installationID string) error {
	return s.messenger.DisableInstallation(installationID)
}

// UpdateMailservers updates information about selected mail servers.
// func (s *Service) UpdateMailservers(nodes []*enode.Node) error {
// 	// if err := s.peerStore.Update(nodes); err != nil {
// 	// 	return err
// 	// }
// 	// if s.connManager != nil {
// 	// 	s.connManager.Notify(nodes)
// 	// }
// 	return nil
// }

// Start is run when a service is started.
// It does nothing in this case but is required by `node.Service` interface.
func (s *Service) StartService() error {
	if s.config.EnableConnectionManager {
		// connectionsTarget := s.config.ConnectionTarget
		// if connectionsTarget == 0 {
		// 	connectionsTarget = defaultConnectionsTarget
		// }
		// maxFailures := s.config.MaxServerFailures
		// // if not defined change server on first expired event
		// if maxFailures == 0 {
		// 	maxFailures = 1
		// }
		// s.connManager = mailservers.NewConnectionManager(server, s.w, connectionsTarget, maxFailures, defaultTimeoutWaitAdded)
		// s.connManager.Start()
		// if err := mailservers.EnsureUsedRecordsAddedFirst(s.peerStore, s.connManager); err != nil {
		// 	return err
		// }
	}
	if s.config.EnableLastUsedMonitor {
		// s.lastUsedMonitor = mailservers.NewLastUsedConnectionMonitor(s.peerStore, s.cache, s.w)
		// s.lastUsedMonitor.Start()
	}
	// s.mailMonitor.Start()
	// s.nodeID = server.PrivateKey
	// s.server = server
	return nil
}

// APIs returns a list of new APIs.
func (s *Service) APIs() []rpc.API {
	apis := []rpc.API{
		{
			Namespace: "shhext",
			Version:   "1.0",
			Service:   NewPublicAPI(s),
			Public:    true,
		},
	}
	return apis
}

// Stop is run when a service is stopped.
func (s *Service) Stop() error {
	log.Info("Stopping shhext service")
	// if s.config.EnableConnectionManager {
	// 	s.connManager.Stop()
	// }
	// if s.config.EnableLastUsedMonitor {
	// 	s.lastUsedMonitor.Stop()
	// }
	// s.requestsRegistry.Clear()
	// s.mailMonitor.Stop()

	if s.cancelMessenger != nil {
		select {
		case <-s.cancelMessenger:
			// channel already closed
		default:
			close(s.cancelMessenger)
			s.cancelMessenger = nil
		}
	}

	if s.messenger != nil {
		if err := s.messenger.Shutdown(); err != nil {
			return err
		}
	}

	return nil
}

func onNegotiatedFilters(filters []*protocolwhisper.Filter) {
	var signalFilters []*signal.Filter
	for _, filter := range filters {

		signalFilter := &signal.Filter{
			ChatID:   filter.ChatID,
			SymKeyID: filter.SymKeyID,
			Listen:   filter.Listen,
			FilterID: filter.FilterID,
			Identity: filter.Identity,
			Topic:    filter.Topic,
		}

		signalFilters = append(signalFilters, signalFilter)
	}
	if len(filters) != 0 {
		handler := PublisherSignalHandler{}
		handler.WhisperFilterAdded(signalFilters)
	}
}

func buildMessengerOptions(config params.ShhextConfig, db *sql.DB, envelopesMonitorConfig *protocolwhisper.EnvelopesMonitorConfig, logger *zap.Logger) []protocol.Option {

	options := []protocol.Option{
		protocol.WithCustomLogger(logger),
		protocol.WithDatabase(db),
		//protocol.WithEnvelopesMonitorConfig(envelopesMonitorConfig),
		protocol.WithOnNegotiatedFilters(onNegotiatedFilters),
	}

	if config.DataSyncEnabled {
		options = append(options, protocol.WithDatasync())
	}

	return options
}
