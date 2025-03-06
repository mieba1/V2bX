package sing

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/InazumaV/V2bX/common/format"
	"github.com/InazumaV/V2bX/common/rate"
	"github.com/InazumaV/V2bX/common/task"

	"github.com/InazumaV/V2bX/limiter"

	"github.com/InazumaV/V2bX/common/counter"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.ConnectionTracker = (*HookServer)(nil)

type ConnEntry struct {
	Conn      net.Conn
	Timestamp time.Time
}

type HookServer struct {
	counter  sync.Map //map[string]*counter.TrafficCounter
	userconn sync.Map //map[string][]*ConnEntry
	Cleanup  *task.Task
}

func (h *HookServer) ModeList() []string {
	return nil
}

func NewHookServer() *HookServer {
	server := &HookServer{
		counter:  sync.Map{},
		userconn: sync.Map{},
	}
	server.Cleanup = &task.Task{
		Interval: 5 * time.Minute,
		Execute:  server.CleanupOldConnections,
	}
	return server
}

func (h *HookServer) RoutedConnection(_ context.Context, conn net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		log.Warn("get limiter for ", m.Inbound, " error: ", err)
		return conn
	}
	taguuid := format.UserTag(m.Inbound, m.User)
	ip := m.Source.Addr.String()
	if b, r := l.CheckLimit(taguuid, ip, true, true); r {
		conn.Close()
		log.Error("[", m.Inbound, "] ", "Limited ", m.User, " by ip or conn")
		return conn
	} else if b != nil {
		conn = rate.NewConnRateLimiter(conn, b)
	}
	if l != nil {
		destStr := m.Destination.AddrString()
		protocol := m.Destination.Network()
		if l.CheckDomainRule(destStr) {
			log.Error(fmt.Sprintf(
				"User %s access domain %s reject by rule",
				m.User,
				destStr))
			conn.Close()
			return conn
		}
		if len(protocol) != 0 {
			if l.CheckProtocolRule(protocol) {
				log.Error(fmt.Sprintf(
					"User %s access protocol %s reject by rule",
					m.User,
					protocol))
				conn.Close()
				return conn
			}
		}
	}
	var t *counter.TrafficCounter
	if c, ok := h.counter.Load(m.Inbound); !ok {
		t = counter.NewTrafficCounter()
		h.counter.Store(m.Inbound, t)
	} else {
		t = c.(*counter.TrafficCounter)
	}

	conn = counter.NewConnCounter(conn, t.GetCounter(m.User))
	entry := &ConnEntry{
		Conn:      conn,
		Timestamp: time.Now(),
	}
	if conns, exist := h.userconn.Load(taguuid); exist {
		if connList, ok := conns.([]*ConnEntry); ok {
			h.userconn.Store(taguuid, append(connList, entry))
		} else {
			h.userconn.Delete(taguuid)
			h.userconn.Store(taguuid, []*ConnEntry{entry})
		}
	} else {
		h.userconn.Store(taguuid, []*ConnEntry{entry})
	}

	return conn
}

func (h *HookServer) RoutedPacketConnection(_ context.Context, conn N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		log.Warn("get limiter for ", m.Inbound, " error: ", err)
		return conn
	}
	ip := m.Source.Addr.String()
	taguuid := format.UserTag(m.Inbound, m.User)
	if b, r := l.CheckLimit(taguuid, ip, false, false); r {
		conn.Close()
		log.Error("[", m.Inbound, "] ", "Limited ", m.User, " by ip or conn")
		return conn
	} else if b != nil {
		//conn = rate.NewPacketConnCounter(conn, b)
	}
	if l != nil {
		destStr := m.Destination.AddrString()
		protocol := m.Destination.Network()
		if l.CheckDomainRule(destStr) {
			log.Error(fmt.Sprintf(
				"User %s access domain %s reject by rule",
				m.User,
				destStr))
			conn.Close()
			return conn
		}
		if len(protocol) != 0 {
			if l.CheckProtocolRule(protocol) {
				log.Error(fmt.Sprintf(
					"User %s access protocol %s reject by rule",
					m.User,
					protocol))
				conn.Close()
				return conn
			}
		}
	}
	var t *counter.TrafficCounter
	if c, ok := h.counter.Load(m.Inbound); !ok {
		t = counter.NewTrafficCounter()
		h.counter.Store(m.Inbound, t)
	} else {
		t = c.(*counter.TrafficCounter)
	}
	conn = counter.NewPacketConnCounter(conn, t.GetCounter(m.User))
	return conn
}

func (h *HookServer) CloseConnections(tag string, uuids []string) error {
	for _, uuid := range uuids {
		taguuid := format.UserTag(tag, uuid)
		v, ok := h.userconn.Load(taguuid)
		if !ok {
			continue
		}
		connList, ok := v.([]*ConnEntry)
		if !ok {
			h.userconn.Delete(taguuid)
			continue
		}

		for _, entry := range connList {
			err := entry.Conn.Close()
			if err != nil {
				log.Error("close conn error: ", err)
			}
		}
		h.userconn.Delete(taguuid)
	}
	return nil
}

func (h *HookServer) CleanupOldConnections() error {
	expiredTime := time.Now().Add(-time.Minute * 30)
	h.userconn.Range(func(key, value interface{}) bool {
		connList, ok := value.([]*ConnEntry)
		if !ok {
			h.userconn.Delete(key)
			return true
		}

		var activeConns []*ConnEntry
		for _, entry := range connList {
			if entry.Timestamp.After(expiredTime) {
				activeConns = append(activeConns, entry)
			}
		}

		if len(activeConns) == 0 {
			h.userconn.Delete(key)
		} else {
			h.userconn.Store(key, activeConns)
		}
		return true
	})
	return nil
}
