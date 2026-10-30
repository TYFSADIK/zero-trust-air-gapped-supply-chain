// Package diode simulates one-way transfer across a data diode.
//
// A diode physically has no return path: no ACKs, no retransmit requests.
// So the sender must (1) frame and checksum everything, (2) add forward
// error correction, and (3) repeat the whole transfer a few times. The
// receiver either reconstructs the exact file or reports precisely what is
// missing; it can never ask.
//
// FEC here is XOR parity over groups of K frames: any single lost frame per
// group is recoverable. Use Reed-Solomon (e.g. klauspost/reedsolomon) for more.
package diode

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
)

const (
	FrameData   = 0
	FrameParity = 1
	hdrLen      = 4 + 4 + 4 + 1 + 4 + 32 + 4 // seq, total, size, kind, group, filehash, crc
)

type Frame struct {
	Seq, Total, FileSize uint32
	Kind                 byte
	Group                uint32
	FileHash             [32]byte
	Data                 []byte
}

func (f Frame) Marshal() []byte {
	b := make([]byte, hdrLen-4, hdrLen+len(f.Data))
	binary.BigEndian.PutUint32(b[0:], f.Seq)
	binary.BigEndian.PutUint32(b[4:], f.Total)
	binary.BigEndian.PutUint32(b[8:], f.FileSize)
	b[12] = f.Kind
	binary.BigEndian.PutUint32(b[13:], f.Group)
	copy(b[17:49], f.FileHash[:])
	b = append(b, f.Data...)
	return binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(b))
}

var ErrCRC = errors.New("frame crc mismatch")

func Unmarshal(b []byte) (Frame, error) {
	if len(b) < hdrLen {
		return Frame{}, ErrCRC
	}
	body, crc := b[:len(b)-4], binary.BigEndian.Uint32(b[len(b)-4:])
	if crc32.ChecksumIEEE(body) != crc {
		return Frame{}, ErrCRC
	}
	f := Frame{Seq: binary.BigEndian.Uint32(body[0:]), Total: binary.BigEndian.Uint32(body[4:]),
		FileSize: binary.BigEndian.Uint32(body[8:]), Kind: body[12], Group: binary.BigEndian.Uint32(body[13:])}
	copy(f.FileHash[:], body[17:49])
	f.Data = append([]byte{}, body[49:]...)
	return f, nil
}

// Encode splits data into frames of `mtu` payload bytes with one parity frame per k data frames.
func Encode(data []byte, mtu, k int) [][]byte {
	h := sha256.Sum256(data)
	total := (len(data) + mtu - 1) / mtu
	var out [][]byte
	for g := 0; g*k < total; g++ {
		parity := make([]byte, mtu)
		for i := g * k; i < min((g+1)*k, total); i++ {
			chunk := make([]byte, mtu)
			copy(chunk, data[i*mtu:min((i+1)*mtu, len(data))])
			for j := range parity {
				parity[j] ^= chunk[j]
			}
			out = append(out, Frame{uint32(i), uint32(total), uint32(len(data)), FrameData, uint32(g), h, chunk}.Marshal())
		}
		out = append(out, Frame{uint32(g), uint32(total), uint32(len(data)), FrameParity, uint32(g), h, parity}.Marshal())
	}
	return out
}

type Receiver struct {
	mtu, k   int
	data     map[uint32][]byte
	parity   map[uint32][]byte
	total    uint32
	size     uint32
	hash     [32]byte
	BadCRC   int
	Repaired int
}

func NewReceiver(mtu, k int) *Receiver {
	return &Receiver{mtu: mtu, k: k, data: map[uint32][]byte{}, parity: map[uint32][]byte{}}
}

func (r *Receiver) Push(b []byte) {
	f, err := Unmarshal(b)
	if err != nil {
		r.BadCRC++
		return
	}
	r.total, r.size, r.hash = f.Total, f.FileSize, f.FileHash
	if f.Kind == FrameData {
		r.data[f.Seq] = f.Data
	} else {
		r.parity[f.Group] = f.Data
	}
}

// Result reconstructs the file, repairing single losses per group with parity.
// On failure it returns the missing frame numbers (to request a re-run of the sender, out of band).
func (r *Receiver) Result() ([]byte, []uint32, error) {
	if r.total == 0 {
		return nil, nil, errors.New("nothing received")
	}
	var missing []uint32
	for g := uint32(0); int(g)*r.k < int(r.total); g++ {
		var lost []uint32
		for i := g * uint32(r.k); i < min((g+1)*uint32(r.k), r.total); i++ {
			if _, ok := r.data[i]; !ok {
				lost = append(lost, i)
			}
		}
		if len(lost) == 1 && r.parity[g] != nil {
			rec := append([]byte{}, r.parity[g]...)
			for i := g * uint32(r.k); i < min((g+1)*uint32(r.k), r.total); i++ {
				if d, ok := r.data[i]; ok {
					for j := range rec {
						rec[j] ^= d[j]
					}
				}
			}
			r.data[lost[0]] = rec
			r.Repaired++
		} else {
			missing = append(missing, lost...)
		}
	}
	if len(missing) > 0 {
		return nil, missing, errors.New("unrecoverable frames missing")
	}
	var buf bytes.Buffer
	for i := uint32(0); i < r.total; i++ {
		buf.Write(r.data[i])
	}
	out := buf.Bytes()[:r.size]
	if sha256.Sum256(out) != r.hash {
		return nil, nil, errors.New("file hash mismatch after reassembly")
	}
	return out, nil, nil
}
