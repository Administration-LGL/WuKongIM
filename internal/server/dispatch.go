package server

import (
	"sync"
	"time"

	"github.com/WuKongIM/WuKongIM/pkg/wklog"
	"github.com/WuKongIM/WuKongIM/pkg/wknet"
	wkproto "github.com/WuKongIM/WuKongIMGoProto"
	"go.uber.org/zap"
)

type Dispatch struct {
	engine *wknet.Engine

	s         *Server
	processor *Processor
	wklog.Log
	framePool sync.Pool
}

func NewDispatch(s *Server) *Dispatch {
	return &Dispatch{
		engine:    wknet.NewEngine(wknet.WithAddr(s.opts.Addr), wknet.WithWSAddr(s.opts.WSAddr), wknet.WithWSSAddr(s.opts.WSSAddr), wknet.WithWSTLSConfig(s.opts.WSTLSConfig)),
		s:         s,
		processor: NewProcessor(s),
		Log:       wklog.NewWKLog("Dispatch"),
		framePool: sync.Pool{
			New: func() any {
				return make([]wkproto.Frame, 20)
			},
		},
	}
}

// 数据统一入口
func (d *Dispatch) dataIn(conn wknet.Conn) error {
	// 返回唤醒缓冲区中的字节数据
	buff, err := conn.Peek(-1)
	if err != nil {
		return err
	}
	if len(buff) == 0 {
		return nil
	}
	//
	data, _ := gnetUnpacket(buff)
	if len(data) == 0 {
		return nil
	}

	// 连接取出后，第一关是认证
	// 没有认证就先认证
	if !conn.IsAuthed() { // conn is not authed must be connect packet
		packet, _, err := d.s.opts.Proto.DecodeFrame(data, wkproto.LatestVersion)
		if err != nil {
			d.Warn("Failed to decode the message", zap.Error(err))
			conn.Close()
			return nil
		}
		if packet == nil {
			d.Warn("message is nil", zap.ByteString("data", data))
			return nil
		}
		// 
		if packet.GetFrameType() != wkproto.CONNECT {
			d.Warn("请先进行连接！")
			conn.Close()
			return nil
		}
		//  process conn auth
		conn.Discard(len(data))
		d.processor.processAuth(conn, packet.(*wkproto.ConnectPacket))
	} else { // authed
		offset := 0
		for len(data) > offset {
			frame, size, err := d.s.opts.Proto.DecodeFrame(data[offset:], uint8(conn.ProtoVersion()))
			if err != nil { //
				d.Warn("Failed to decode the message", zap.Error(err))
				conn.Close()
				return err
			}
			if frame == nil {
				break
			}

			// 统计
			d.s.monitor.UpstreamPackageAdd(1)
			d.s.monitor.UpstreamTrafficAdd(size)
			d.s.stats.inMsgs.Add(1)
			d.s.stats.inBytes.Add(int64(size))

			connStats := conn.ConnStats()
			connStats.InMsgs.Add(1)
			connStats.InBytes.Add(int64(size))

			// context
			connCtx := conn.Context().(*connContext)
			connCtx.putFrame(frame)
			offset += size
		}
		// process frames
		// 解析完成后，删除已经解析了的缓存
		conn.Discard(offset)

		d.processor.process(conn)
	}
	return nil
}

// 数据统一出口
func (d *Dispatch) dataOut(conn wknet.Conn, frames ...wkproto.Frame) {
	if len(frames) == 0 {
		return
	}

	// 统计
	connStats := conn.ConnStats()
	d.s.monitor.DownstreamPackageAdd(len(frames))
	d.s.outMsgs.Add(int64(len(frames)))
	connStats.OutMsgs.Add(int64(len(frames)))

	wsConn, wsok := conn.(wknet.IWSConn) // websocket连接
	for _, frame := range frames {
		data, err := d.s.opts.Proto.EncodeFrame(frame, uint8(conn.ProtoVersion()))
		if err != nil {
			d.Warn("Failed to encode the message", zap.Error(err))
		} else {
			// 统计
			dataLen := len(data)
			d.s.monitor.DownstreamTrafficAdd(dataLen)
			d.s.outBytes.Add(int64(dataLen))
			connStats.OutBytes.Add(int64(dataLen))

			if wsok {
				err = wsConn.WriteServerBinary(data)
				if err != nil {
					d.Warn("Failed to write the message", zap.Error(err))
				}

			} else {
				_, err = conn.WriteToOutboundBuffer(data)
				if err != nil {
					d.Warn("Failed to write the message", zap.Error(err))
				}
			}

		}
	}
	conn.WakeWrite()

}

func (d *Dispatch) onConnect(conn wknet.Conn) error {
	// 设置了超时时间，并加入定时任务
	conn.SetMaxIdle(time.Second * 2) // 在认证之前，连接最多空闲2秒
	d.s.monitor.ConnInc()
	return nil
}

func (d *Dispatch) onClose(conn wknet.Conn) {
	d.Debug("conn close for OnClose", zap.Any("conn", conn))
	d.s.connManager.RemoveConn(conn)
	d.processor.processClose(conn)
	d.s.monitor.ConnDec()
}

func (d *Dispatch) Start() error {

	d.engine.OnConnect(d.onConnect)
	d.engine.OnData(d.dataIn)
	d.engine.OnClose(d.onClose)

	err := d.engine.Start()
	if err != nil {
		return err
	}
	return err
}

func (d *Dispatch) Stop() error {
	err := d.engine.Stop()
	if err != nil {
		return err
	}
	return err
}

// 找到多条条完整消息
func gnetUnpacket(buff []byte) ([]byte, error) {
	// buff, _ := c.Peek(-1)
	if len(buff) <= 0 {
		return nil, nil
	}
	offset := 0

	for len(buff) > offset {
		typeAndFlags := buff[offset]
		// 高4位表示类型
		packetType := wkproto.FrameType(typeAndFlags >> 4)
		if packetType == wkproto.PING || packetType == wkproto.PONG {
			offset++
			continue
		}
		reminLen, readSize, has := decodeLength(buff[offset+1:])
		if !has {
			break
		}
		// dataEnd: 表示一个完整的数据包占用了的字节数
		// offset: 偏移量
		// reminlen: 可变头占用的长度(存储有多少payload)
		// readsize: payload 长度
		// +1 : 表示固定头部 1
		dataEnd := offset + readSize + reminLen + 1
		if len(buff) >= dataEnd { // 总数据长度大于当前包数据长度 说明还有包可读。
			offset = dataEnd
			continue
		} else {
			break
		}
	}

	if offset > 0 {
		return buff[:offset], nil
	}

	return nil, nil
}

// 返回的结果
// offset表示用了多少字节来记录内容部分有多大
// rlength 表示内容部分的长度
func decodeLength(data []byte) (int, int, bool) {
	var rLength uint32
	var multiplier uint32
	offset := 0
	// WK协议规定，可变长度最长就是4次节，当multiplier>=27，说明可变的4字节一定读完了，
	// 4*8 = 32, 32-3 = 29, 29
	for multiplier < 27 { //fix: Infinite '(digit & 128) == 1' will cause the dead loop
		if offset >= len(data) {
			return 0, 0, false
		}
		digit := data[offset]
		offset++
		// 127: 因为最高位表示可变值是否读取完
		rLength |= uint32(digit&127) << multiplier
		// 表示是否读完
		if (digit & 128) == 0 {
			break
		}
		// 1 1111111 1 1111111 1 1111111 11111111
		// 因为每个字节只有7bit是代表值的，所以每次多移7
		// 第一次读取的就表示 0~7，第二次就是 7~14
		multiplier += 7
	}
	// 返回值:可变长区间存储的值，用了几个字节
	return int(rLength), offset, true
}
