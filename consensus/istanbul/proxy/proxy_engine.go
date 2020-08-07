// Copyright 2017 The celo Authors
// This file is part of the celo library.
//
// The celo library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The celo library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the celo library. If not, see <http://www.gnu.org/licenses/>.

package proxy

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// BackendForProxyEngine provides the Istanbul backend application specific functions for Istanbul proxy engine
type BackendForProxyEngine interface {
	// IsProxy returns true if this node is a proxy
	IsProxy() bool

	// SelfNode returns the owner's node (if this is a proxy, it will return the external node)
	SelfNode() *enode.Node

	// Multicast sends a message to it's connected nodes filtered on the 'addresses' parameter (where each address
	// is associated with those node's signing key)
	// If sendToSelf is set to true, then the function will send an event to self via a message event
	Multicast(addresses []common.Address, payload []byte, ethMsgCode uint64, sendToSelf bool) error

	// Unicast will asynchronously send a celo message to peer
	Unicast(peer consensus.Peer, payload []byte, ethMsgCode uint64)

	// GetValEnodeTableEntries retrieves the entries in the valEnodeTable filtered on the "validators" parameter.
	// If the parameter is nil, then no filter will be applied.
	GetValEnodeTableEntries(validators []common.Address) (map[common.Address]*istanbul.AddressEntry, error)

	// RewriteValEnodeTableEntries will rewrite the val enode table with "entries".
	RewriteValEnodeTableEntries(entries map[common.Address]*istanbul.AddressEntry) error

	// SetEnodeCertificateMsgs will set this node's enodeCertificate to be used for connection handshakes
	SetEnodeCertificateMsgMap(enodeCertificateMsgMap map[enode.ID]*istanbul.EnodeCertMsg) error

	// VerifyPendingBlockValidatorSignature is a message validation function to verify that a message's sender is within the validator set
	// of the current pending block and that the message's address field matches the message's signature's signer
	VerifyPendingBlockValidatorSignature(data []byte, sig []byte) (common.Address, error)

	// VerifyValidatorConnectionSetSignature is a message validation function to verify that a message's sender is within the
	// validator connection set and that the message's address field matches the message's signature's signer
	VerifyValidatorConnectionSetSignature(data []byte, sig []byte) (common.Address, error)
}

type proxyEngine struct {
	config  *istanbul.Config
	logger  log.Logger
	backend BackendForProxyEngine

	isRunning   bool
	isRunningMu sync.RWMutex

	loopWG sync.WaitGroup
	quit   chan struct{} // Used to notify to the thread to quit

	addValidator    chan *enode.Node
	removeValidator chan *enode.Node

	// Proxied Validators set and count of authorized addresses
	proxiedValidators   map[consensus.Peer]bool
	authorizedAddresses map[common.Address]int
}

// New creates a new proxy engine.
func NewProxyEngine(backend BackendForProxyEngine, config *istanbul.Config) (ProxyEngine, error) {
	if !backend.IsProxy() {
		return nil, ErrNodeNotProxy
	}

	p := &proxyEngine{
		config:  config,
		logger:  log.New(),
		backend: backend,

		addValidator:    make(chan *enode.Node),
		removeValidator: make(chan *enode.Node),

		proxiedValidators:   make(map[consensus.Peer]bool),
		authorizedAddresses: make(map[common.Address]int),
	}

	return p, nil
}

// Start starts the proxy engine.
func (p *proxyEngine) Start() error {
	p.isRunningMu.Lock()
	defer p.isRunningMu.Unlock()

	if p.isRunning {
		return ErrStartedProxyEngine
	}
	p.loopWG.Add(1)
	p.quit = make(chan struct{})
	go p.run()

	p.isRunning = true
	p.logger.Warn("Proxy engine started")
	return nil
}

// Stop stops the proxy engine.
func (p *proxyEngine) Stop() error {
	p.isRunningMu.Lock()
	defer p.isRunningMu.Unlock()

	if !p.isRunning {
		return ErrStoppedProxyEngine
	}

	close(p.quit)
	p.loopWG.Wait()

	p.isRunning = false
	p.logger.Warn("Proxy engine stopped")
	return nil
}

func (p *proxyEngine) HandleMsg(peer consensus.Peer, msgCode uint64, payload []byte) (bool, error) {
	if msgCode == istanbul.ValEnodesShareMsg {
		return p.handleValEnodesShareMsg(peer, payload)
	} else if msgCode == istanbul.FwdMsg {
		return p.handleForwardMsg(peer, payload)
	} else if msgCode == istanbul.ConsensusMsg {
		return p.handleConsensusMsg(peer, payload)
	} else if msgCode == istanbul.EnodeCertificateMsg {
		return p.handleEnodeCertificateMsg(peer, payload)
	}

	return false, nil
}

// Note, this only needs to be implemented once we check incoming connections
// against acceptable nodekeys / addresses
func (p *proxyEngine) run() {
	defer p.loopWG.Done()
	for {
		select {
		case <-p.quit:
			// The proxy engine was stopped
			return
		}
	}
}

// Callback once validator dials us and is properly registered.
func (p *proxyEngine) RegisterProxiedValidatorPeer(proxiedValidatorPeer consensus.Peer) {
	// TODO: Does this need a lock?
	pubKey := proxiedValidatorPeer.Node().Pubkey()
	addr := crypto.PubkeyToAddress(*pubKey)
	logger := p.logger.New("func", "RegisterProxiedValidatorPeer")
	logger.Warn("Adding validator", "addr", addr, "ID", proxiedValidatorPeer.Node().ID(), "enode", proxiedValidatorPeer.Node())
	p.authorizedAddresses[addr] = p.authorizedAddresses[addr] + 1
	p.proxiedValidators[proxiedValidatorPeer] = true
}

func (p *proxyEngine) UnregisterProxiedValidatorPeer(proxiedValidatorPeer consensus.Peer) {
	pubKey := proxiedValidatorPeer.Node().Pubkey()
	addr := crypto.PubkeyToAddress(*pubKey)
	logger := p.logger.New("func", "UnregisterProxiedValidatorPeer")
	logger.Warn("Removing validator", "addr", addr, "enode", proxiedValidatorPeer.Node())
	p.authorizedAddresses[addr] = p.authorizedAddresses[addr] - 1
	if p.authorizedAddresses[addr] == 0 {
		delete(p.authorizedAddresses, addr)
	}
	delete(p.proxiedValidators, proxiedValidatorPeer)
}

func (p *proxyEngine) GetProxiedValidatorsInfo() ([]ProxiedValidatorInfo, error) {
	proxiedValidatorsInfo := []ProxiedValidatorInfo{}
	for proxiedValidatorPeer := range p.proxiedValidators {
		pubKey := proxiedValidatorPeer.Node().Pubkey()
		addr := crypto.PubkeyToAddress(*pubKey)
		proxiedValidatorInfo := ProxiedValidatorInfo{
			Address:  addr,
			IsPeered: true,
			Node:     proxiedValidatorPeer.Node()}
		proxiedValidatorsInfo = append(proxiedValidatorsInfo, proxiedValidatorInfo)
	}
	return proxiedValidatorsInfo, nil
}

// SendMsgToProxiedValidators will send a `celo` message to the proxied validators.
func (p *proxyEngine) SendMsgToProxiedValidators(msgCode uint64, msg *istanbul.Message) error {
	logger := p.logger.New("func", "SendMsgToProxiedValidators")
	if len(p.proxiedValidators) == 0 {
		logger.Warn("Proxy has no connected proxied validator.  Not sending message.")
		return nil
	}
	payload, err := msg.Payload()
	if err != nil {
		logger.Error("Error getting payload of message", "err", err)
		return err
	}
	for proxiedValidator := range p.proxiedValidators {
		p.backend.Unicast(proxiedValidator, payload, msgCode)
	}
	return nil
}
