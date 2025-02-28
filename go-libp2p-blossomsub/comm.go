package blossomsub

import (
	"context"
	"encoding/binary"
	"io"
	"time"

	pool "github.com/libp2p/go-buffer-pool"
	"github.com/multiformats/go-varint"
	"google.golang.org/protobuf/proto"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"

	pb "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
)

// get the initial RPC containing all of our subscriptions to send to new peers
func (p *PubSub) getHelloPacket() *RPC {
	var rpc = &RPC{
		RPC: new(pb.RPC),
	}

	subscriptions := make(map[string]bool)

	for t := range p.mySubs {
		subscriptions[t] = true
	}

	for t := range p.myRelays {
		subscriptions[t] = true
	}

	for t := range subscriptions {
		as := &pb.RPC_SubOpts{
			Bitmask:   []byte(t),
			Subscribe: true,
		}
		rpc.Subscriptions = append(rpc.Subscriptions, as)
	}
	return rpc
}

func (p *PubSub) handleNewStream(s network.Stream) {
	peer := s.Conn().RemotePeer()

	p.inboundStreamsMx.Lock()
	other, dup := p.inboundStreams[peer]
	if dup {
		log.Debugf("duplicate inbound stream from %s; resetting other stream", peer)
		other.Reset()
	}
	p.inboundStreams[peer] = s
	p.inboundStreamsMx.Unlock()

	r := msgio.NewVarintReaderSize(s, p.hardMaxMessageSize)
	read := func() (*RPC, error) {
		n, err := r.NextMsgLen()
		if err != nil {
			return nil, err
		}
		if n == 0 {
			_, err := r.Read(nil)
			return nil, err
		}
		buf := poolGet(n, p.softMaxMessageSize)
		defer poolPut(buf, p.softMaxMessageSize)
		if _, err := r.Read(buf); err != nil {
			return nil, err
		}
		rpc := new(pb.RPC)
		if err := rpc.Unmarshal(buf); err != nil {
			return nil, err
		}
		return &RPC{RPC: rpc, from: peer}, nil
	}
	for {
		rpc, err := read()
		if err != nil {
			if err != io.EOF {
				s.Reset()
				log.Debugf("error reading rpc from %s: %s", s.Conn().RemotePeer(), err)
			} else {
				// Just be nice. They probably won't read this
				// but it doesn't hurt to send it.
				s.Close()
			}

			p.inboundStreamsMx.Lock()
			if p.inboundStreams[peer] == s {
				delete(p.inboundStreams, peer)
			}
			p.inboundStreamsMx.Unlock()
			return
		}
		if rpc == nil {
			continue
		}

		select {
		case p.incoming <- rpc:
		case <-p.ctx.Done():
			// Close is useless because the other side isn't reading.
			s.Reset()
			p.inboundStreamsMx.Lock()
			if p.inboundStreams[peer] == s {
				delete(p.inboundStreams, peer)
			}
			p.inboundStreamsMx.Unlock()
			return
		}
	}
}

func (p *PubSub) notifyPeerDead(pid peer.ID) {
	p.peerDeadPrioLk.RLock()
	p.peerDeadMx.Lock()
	p.peerDeadPend[pid] = struct{}{}
	p.peerDeadMx.Unlock()
	p.peerDeadPrioLk.RUnlock()

	select {
	case p.peerDead <- struct{}{}:
	default:
	}
}

func (p *PubSub) handleNewPeer(ctx context.Context, pid peer.ID, q *rpcQueue) {
	s, err := p.host.NewStream(p.ctx, pid, p.rt.Protocols()...)
	if err != nil {
		log.Debug("opening new stream to peer: ", err, pid)

		select {
		case p.newPeerError <- pid:
		case <-ctx.Done():
		}

		return
	}

	go p.handleSendingMessages(ctx, s, q)
	go p.handlePeerDead(s)
	select {
	case p.newPeerStream <- s:
	case <-ctx.Done():
	}
}

func (p *PubSub) handleNewPeerWithBackoff(ctx context.Context, pid peer.ID, backoff time.Duration, q *rpcQueue) {
	select {
	case <-time.After(backoff):
		p.handleNewPeer(ctx, pid, q)
	case <-ctx.Done():
		return
	}
}

func (p *PubSub) handlePeerDead(s network.Stream) {
	pid := s.Conn().RemotePeer()

	_, err := s.Read([]byte{0})
	if err == nil {
		log.Debugf("unexpected message from %s", pid)
	}

	s.Reset()
	p.notifyPeerDead(pid)
}

func (p *PubSub) handleSendingMessages(ctx context.Context, s network.Stream, q *rpcQueue) {
	writeRPC := func(rpc *RPC) error {
		size := uint64(rpc.Size())
		buf := poolGet(varint.UvarintSize(size)+int(size), p.softMaxMessageSize)
		defer poolPut(buf, p.softMaxMessageSize)
		n := binary.PutUvarint(buf, size)
		_, err := rpc.MarshalTo(buf[n:])
		if err != nil {
			return err
		}
		_, err = s.Write(buf)
		return err
	}
	defer s.Close()
	defer s.Reset()
	for {
		rpc, err := q.Pop(ctx)
		if err != nil {
			log.Debugf("pop RPC from queue: %s", err)
			return
		}
		if err := writeRPC(rpc); err != nil {
			log.Debugf("writing message to %s: %s", s.Conn().RemotePeer(), err)
			return
		}
	}
}

func rpcWithSubs(subs ...*pb.RPC_SubOpts) *RPC {
	return &RPC{
		RPC: &pb.RPC{
			Subscriptions: subs,
		},
	}
}

func rpcWithMessages(msgs ...*pb.Message) *RPC {
	return &RPC{RPC: &pb.RPC{Publish: msgs}}
}

func rpcWithControl(msgs []*pb.Message,
	ihave []*pb.ControlIHave,
	iwant []*pb.ControlIWant,
	graft []*pb.ControlGraft,
	prune []*pb.ControlPrune,
	idontwant []*pb.ControlIDontWant) *RPC {
	return &RPC{
		RPC: &pb.RPC{
			Publish: msgs,
			Control: &pb.ControlMessage{
				Ihave:     ihave,
				Iwant:     iwant,
				Graft:     graft,
				Prune:     prune,
				Idontwant: idontwant,
			},
		},
	}
}

func copyRPC(rpc *RPC) *RPC {
	res := new(RPC)
	*res = *rpc
	res.RPC = (proto.Clone(rpc.RPC)).(*pb.RPC)
	return res
}

// poolGet returns a buffer of length n from the pool if n < limit, otherwise it allocates a new buffer.
func poolGet(n int, limit int) []byte {
	if n >= limit {
		return make([]byte, n)
	}
	return pool.Get(n)
}

// poolPut returns a buffer to the pool if its length is less than limit.
func poolPut(buf []byte, limit int) {
	if len(buf) >= limit {
		return
	}
	pool.Put(buf)
}
