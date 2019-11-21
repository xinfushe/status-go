module github.com/status-im/status-go

go 1.13

replace github.com/ethereum/go-ethereum v1.9.5 => github.com/status-im/go-ethereum v1.9.5-status.5

replace github.com/Sirupsen/logrus v1.4.2 => github.com/sirupsen/logrus v1.4.2

replace github.com/docker/docker => github.com/docker/engine v1.4.2-0.20190717161051-705d9623b7c1

replace github.com/gomarkdown/markdown => github.com/status-im/markdown v0.0.0-20191113114344-af599402d015

require (
	github.com/beevik/ntp v0.2.0
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/btcsuite/btcutil v0.0.0-20190425235716-9e5f4b9a998d
	github.com/cenkalti/backoff/v3 v3.0.0
	github.com/ethereum/go-ethereum v1.9.5
	github.com/gballet/go-libpcsclite v0.0.0-20191108122812-4678299bea08 // indirect
	github.com/go-playground/locales v0.12.1 // indirect
	github.com/go-playground/universal-translator v0.16.0 // indirect
	github.com/golang-migrate/migrate/v4 v4.7.0 // indirect
	github.com/golang/mock v1.3.1
	github.com/golang/protobuf v1.3.2
	github.com/gomarkdown/markdown v0.0.0-00010101000000-000000000000
	github.com/google/uuid v1.1.1
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a
	github.com/karalabe/usb v0.0.0-20191104083709-911d15fe12a9 // indirect
	github.com/leodido/go-urn v1.1.0 // indirect
	github.com/lib/pq v1.2.0
	github.com/libp2p/go-libp2p v0.4.0 // indirect
	github.com/libp2p/go-libp2p-core v0.2.3
	github.com/lucasb-eyer/go-colorful v1.0.3
	github.com/mattn/go-pointer v0.0.0-20190911064623-a0a44394634f
	github.com/multiformats/go-multiaddr v0.1.1
	github.com/mutecomm/go-sqlcipher v0.0.0-20190227152316-55dbde17881f
	github.com/okzk/sdnotify v0.0.0-20180710141335-d9becc38acbd
	github.com/pborman/uuid v1.2.0
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v1.2.1
	github.com/russolsen/ohyeah v0.0.0-20160324131710-f4938c005315 // indirect
	github.com/russolsen/same v0.0.0-20160222130632-f089df61f51d // indirect
	github.com/russolsen/transit v0.0.0-20180705123435-0794b4c4505a
	github.com/status-im/doubleratchet v3.0.0+incompatible
	github.com/status-im/keycard-go v0.0.0-20191119114148-6dd40a46baa0 // indirect
	github.com/status-im/migrate/v4 v4.6.2-status.2
	github.com/status-im/rendezvous v1.3.0
	github.com/status-im/tcp-shaker v0.0.0-20191114194237-215893130501
	github.com/status-im/whisper v1.6.1
	github.com/stretchr/testify v1.4.0
	github.com/syndtr/goleveldb v1.0.0
	github.com/vacp2p/mvds v0.0.25
	github.com/wealdtech/go-ens/v3 v3.0.9
	go.uber.org/atomic v1.5.1 // indirect
	go.uber.org/multierr v1.4.0 // indirect
	go.uber.org/zap v1.10.0
	golang.org/x/crypto v0.0.0-20191029031824-8986dd9e96cf
	golang.org/x/text v0.3.2
	gopkg.in/go-playground/assert.v1 v1.2.1 // indirect
	gopkg.in/go-playground/validator.v9 v9.29.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)
