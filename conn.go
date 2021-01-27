package ldappool

import (
	"crypto/tls"
	"github.com/go-ldap/ldap/v3"
	"log"
	"sync"
	"time"
)

// PoolConn implements Client to override the Close() method
type PoolConn struct {
	Conn     ldap.Client
	c        *channelPool
	unusable bool
	closeAt  []uint16
	mu       sync.RWMutex
}

func (p *PoolConn) Start() {
	p.Conn.Start()
}

func (p *PoolConn) StartTLS(config *tls.Config) error {
	// FIXME - check if already TLS and then ignore?
	return p.Conn.StartTLS(config)
}

// Close puts the given connects back to the pool instead of closing it.
func (p *PoolConn) Close() {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.unusable {
		log.Printf("Closing unusable connection")
		if p.Conn != nil {
			p.Conn.Close()
		}
		return
	}
	p.c.put(p.Conn)
}

func (p *PoolConn) SimpleBind(simpleBindRequest *ldap.SimpleBindRequest) (*ldap.SimpleBindResult, error) {
	res, err := p.Conn.SimpleBind(simpleBindRequest)
	p.autoClose(err)
	return res, err
}

func (p *PoolConn) Bind(username, password string) error {
	err := p.Conn.Bind(username, password)
	p.autoClose(err)
	return err
}

// MarkUnusable marks the connection not usable any more, to let the pool close it
// instead of returning it to pool.
func (p *PoolConn) MarkUnusable() {
	p.mu.Lock()
	p.unusable = true
	p.mu.Unlock()
}

func (p *PoolConn) autoClose(err error) {
	for _, code := range p.closeAt {
		if ldap.IsErrorWithCode(err, code) {
			p.MarkUnusable()
			return
		}
	}
}

func (p *PoolConn) SetTimeout(t time.Duration) {
	p.Conn.SetTimeout(t)
}

func (p *PoolConn) Add(addRequest *ldap.AddRequest) error {
	err := p.Conn.Add(addRequest)
	p.autoClose(err)
	return err
}

func (p *PoolConn) Del(delRequest *ldap.DelRequest) error {
	err := p.Conn.Del(delRequest)
	p.autoClose(err)
	return err
}

func (p *PoolConn) Modify(modifyRequest *ldap.ModifyRequest) error {
	err := p.Conn.Modify(modifyRequest)
	p.autoClose(err)
	return err
}

func (p *PoolConn) Compare(dn, attribute, value string) (bool, error) {
	res, err := p.Conn.Compare(dn, attribute, value)
	p.autoClose(err)
	return res, err
}

func (p *PoolConn) PasswordModify(passwordModifyRequest *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	res, err := p.Conn.PasswordModify(passwordModifyRequest)
	p.autoClose(err)
	return res, err
}

func (p *PoolConn) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	res, err := p.Conn.Search(searchRequest)
	p.autoClose(err)
	return res, err
}
func (p *PoolConn) SearchWithPaging(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	res, err := p.Conn.SearchWithPaging(searchRequest, pagingSize)
	p.autoClose(err)
	return res, err
}
