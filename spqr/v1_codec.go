// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//
// Codec between the in-memory v1State and its proto.V1State wire form, ported
// from SparsePostQuantumRatchet v1.5.1 src/v1/chunked/states/serialize.rs
// (States::into_pb / from_pb) together with the per-state into_pb/from_pb in
// send_ek.rs / send_ct.rs. The top-level orchestration (spqr.go) serializes the
// v1State into PqRatchetState between every send/recv step, so this codec is on
// the hot path and must round-trip exactly.
//
// Each of the 11 states maps to one V1State oneof variant. The proto splits each
// state into an "unchunked" core (uc: epoch, authenticator, and the KEM byte
// artifacts that state holds) plus the live chunk-transport encoders/decoders.
// The unchunked core type per state (see the proto V1State.Unchunked.* messages):
//
//	KeysUnsampled        uc=KeysUnsampled      {epoch, auth}
//	KeysSampled          uc=HeaderSent         {epoch, auth, ek, dk}   + sendingHdr
//	HeaderSent           uc=EkSent             {epoch, auth, dk}       + sendingEk, recvingCt1
//	Ct1Received          uc=EkSentCt1Received  {epoch, auth, dk, ct1}  + sendingEk
//	EkSentCt1Received    uc=EkSentCt1Received  {epoch, auth, dk, ct1}  + recvingCt2
//	NoHeaderReceived     uc=NoHeaderReceived   {epoch, auth}           + recvingHdr
//	HeaderReceived       uc=HeaderReceived     {epoch, auth, hdr}      + recvingEk
//	Ct1Sampled           uc=Ct1Sent            {epoch, auth, hdr, es, ct1} + sendingCt1, recvingEk
//	EkReceivedCt1Sampled uc=Ct1SentEkReceived  {epoch, auth, es, ek, ct1}  + sendingCt1
//	Ct1Acknowledged      uc=Ct1Sent            {epoch, auth, hdr, es, ct1} + recvingEk
//	Ct2Sampled           uc=Ct2Sent            {epoch, auth}           + sendingCt2

package spqr

import (
	"errors"
	"fmt"

	"github.com/GoCodeAlone/libsignal-go/internal/spqr/chunked"
	"github.com/GoCodeAlone/libsignal-go/proto"
)

// ErrV1StateDecode is returned when a proto.V1State cannot be decoded into a
// v1State (missing inner variant, missing required sub-message, or a malformed
// encoder/decoder). Mirrors the reference Error::StateDecode.
var ErrV1StateDecode = errors.New("spqr: invalid v1 state")

// v1StateToProto serializes a v1State into its proto.V1State oneof variant.
func v1StateToProto(s *v1State) *proto.V1State {
	auth := s.auth.toProto()
	out := &proto.V1State{}
	switch s.tag {
	case tagKeysUnsampled:
		out.InnerState = &proto.V1State_KeysUnsampled{KeysUnsampled: &proto.V1State_Chunked_KeysUnsampled{
			Uc: &proto.V1State_Unchunked_KeysUnsampled{Epoch: s.epoch, Auth: auth},
		}}
	case tagKeysSampled:
		out.InnerState = &proto.V1State_KeysSampled{KeysSampled: &proto.V1State_Chunked_KeysSampled{
			Uc:         &proto.V1State_Unchunked_HeaderSent{Epoch: s.epoch, Auth: auth, Ek: s.ek, Dk: s.dk},
			SendingHdr: chunked.EncoderToProto(s.sendingHdr),
		}}
	case tagHeaderSent:
		out.InnerState = &proto.V1State_HeaderSent{HeaderSent: &proto.V1State_Chunked_HeaderSent{
			Uc:           &proto.V1State_Unchunked_EkSent{Epoch: s.epoch, Auth: auth, Dk: s.dk},
			SendingEk:    chunked.EncoderToProto(s.sendingEk),
			ReceivingCt1: chunked.DecoderToProto(s.recvingCt1),
		}}
	case tagCt1Received:
		out.InnerState = &proto.V1State_Ct1Received{Ct1Received: &proto.V1State_Chunked_Ct1Received{
			Uc:        &proto.V1State_Unchunked_EkSentCt1Received{Epoch: s.epoch, Auth: auth, Dk: s.dk, Ct1: s.ct1},
			SendingEk: chunked.EncoderToProto(s.sendingEk),
		}}
	case tagEkSentCt1Received:
		out.InnerState = &proto.V1State_EkSentCt1Received{EkSentCt1Received: &proto.V1State_Chunked_EkSentCt1Received{
			Uc:           &proto.V1State_Unchunked_EkSentCt1Received{Epoch: s.epoch, Auth: auth, Dk: s.dk, Ct1: s.ct1},
			ReceivingCt2: chunked.DecoderToProto(s.recvingCt2),
		}}
	case tagNoHeaderReceived:
		out.InnerState = &proto.V1State_NoHeaderReceived{NoHeaderReceived: &proto.V1State_Chunked_NoHeaderReceived{
			Uc:           &proto.V1State_Unchunked_NoHeaderReceived{Epoch: s.epoch, Auth: auth},
			ReceivingHdr: chunked.DecoderToProto(s.recvingHdr),
		}}
	case tagHeaderReceived:
		out.InnerState = &proto.V1State_HeaderReceived{HeaderReceived: &proto.V1State_Chunked_HeaderReceived{
			Uc:          &proto.V1State_Unchunked_HeaderReceived{Epoch: s.epoch, Auth: auth, Hdr: s.hdr},
			ReceivingEk: chunked.DecoderToProto(s.recvingEk),
		}}
	case tagCt1Sampled:
		out.InnerState = &proto.V1State_Ct1Sampled{Ct1Sampled: &proto.V1State_Chunked_Ct1Sampled{
			Uc:          &proto.V1State_Unchunked_Ct1Sent{Epoch: s.epoch, Auth: auth, Hdr: s.hdr, Es: s.es, Ct1: s.ct1},
			SendingCt1:  chunked.EncoderToProto(s.sendingCt1),
			ReceivingEk: chunked.DecoderToProto(s.recvingEk),
		}}
	case tagEkReceivedCt1Sampled:
		out.InnerState = &proto.V1State_EkReceivedCt1Sampled{EkReceivedCt1Sampled: &proto.V1State_Chunked_EkReceivedCt1Sampled{
			Uc:         &proto.V1State_Unchunked_Ct1SentEkReceived{Epoch: s.epoch, Auth: auth, Es: s.es, Ek: s.ek, Ct1: s.ct1},
			SendingCt1: chunked.EncoderToProto(s.sendingCt1),
		}}
	case tagCt1Acknowledged:
		out.InnerState = &proto.V1State_Ct1Acknowledged{Ct1Acknowledged: &proto.V1State_Chunked_Ct1Acknowledged{
			Uc:          &proto.V1State_Unchunked_Ct1Sent{Epoch: s.epoch, Auth: auth, Hdr: s.hdr, Es: s.es, Ct1: s.ct1},
			ReceivingEk: chunked.DecoderToProto(s.recvingEk),
		}}
	case tagCt2Sampled:
		out.InnerState = &proto.V1State_Ct2Sampled{Ct2Sampled: &proto.V1State_Chunked_Ct2Sampled{
			Uc:         &proto.V1State_Unchunked_Ct2Sent{Epoch: s.epoch, Auth: auth},
			SendingCt2: chunked.EncoderToProto(s.sendingCt2),
		}}
	}
	return out
}

// v1StateFromProto reconstructs a v1State from a proto.V1State oneof variant. An
// absent or unrecognized inner variant, a missing uc, or a malformed
// encoder/decoder yields ErrV1StateDecode.
func v1StateFromProto(pb *proto.V1State) (*v1State, error) {
	if pb == nil {
		return nil, ErrV1StateDecode
	}
	switch v := pb.GetInnerState().(type) {
	case *proto.V1State_KeysUnsampled:
		uc := v.KeysUnsampled.GetUc()
		if uc == nil {
			return nil, ErrV1StateDecode
		}
		return &v1State{tag: tagKeysUnsampled, epoch: uc.GetEpoch(), auth: authFrom(uc.GetAuth())}, nil

	case *proto.V1State_KeysSampled:
		c := v.KeysSampled
		uc := c.GetUc()
		if uc == nil {
			return nil, ErrV1StateDecode
		}
		enc, err := decEncoder(c.GetSendingHdr())
		if err != nil {
			return nil, err
		}
		return &v1State{
			tag: tagKeysSampled, epoch: uc.GetEpoch(), auth: authFrom(uc.GetAuth()),
			ek: uc.GetEk(), dk: uc.GetDk(), sendingHdr: enc,
		}, nil

	case *proto.V1State_HeaderSent:
		c := v.HeaderSent
		uc := c.GetUc()
		if uc == nil {
			return nil, ErrV1StateDecode
		}
		enc, err := decEncoder(c.GetSendingEk())
		if err != nil {
			return nil, err
		}
		dec, err := decDecoder(c.GetReceivingCt1())
		if err != nil {
			return nil, err
		}
		return &v1State{
			tag: tagHeaderSent, epoch: uc.GetEpoch(), auth: authFrom(uc.GetAuth()),
			dk: uc.GetDk(), sendingEk: enc, recvingCt1: dec,
		}, nil

	case *proto.V1State_Ct1Received:
		c := v.Ct1Received
		uc := c.GetUc()
		if uc == nil {
			return nil, ErrV1StateDecode
		}
		enc, err := decEncoder(c.GetSendingEk())
		if err != nil {
			return nil, err
		}
		return &v1State{
			tag: tagCt1Received, epoch: uc.GetEpoch(), auth: authFrom(uc.GetAuth()),
			dk: uc.GetDk(), ct1: uc.GetCt1(), sendingEk: enc,
		}, nil

	case *proto.V1State_EkSentCt1Received:
		c := v.EkSentCt1Received
		uc := c.GetUc()
		if uc == nil {
			return nil, ErrV1StateDecode
		}
		dec, err := decDecoder(c.GetReceivingCt2())
		if err != nil {
			return nil, err
		}
		return &v1State{
			tag: tagEkSentCt1Received, epoch: uc.GetEpoch(), auth: authFrom(uc.GetAuth()),
			dk: uc.GetDk(), ct1: uc.GetCt1(), recvingCt2: dec,
		}, nil

	case *proto.V1State_NoHeaderReceived:
		c := v.NoHeaderReceived
		uc := c.GetUc()
		if uc == nil {
			return nil, ErrV1StateDecode
		}
		dec, err := decDecoder(c.GetReceivingHdr())
		if err != nil {
			return nil, err
		}
		return &v1State{
			tag: tagNoHeaderReceived, epoch: uc.GetEpoch(), auth: authFrom(uc.GetAuth()), recvingHdr: dec,
		}, nil

	case *proto.V1State_HeaderReceived:
		c := v.HeaderReceived
		uc := c.GetUc()
		if uc == nil {
			return nil, ErrV1StateDecode
		}
		dec, err := decDecoder(c.GetReceivingEk())
		if err != nil {
			return nil, err
		}
		return &v1State{
			tag: tagHeaderReceived, epoch: uc.GetEpoch(), auth: authFrom(uc.GetAuth()),
			hdr: uc.GetHdr(), recvingEk: dec,
		}, nil

	case *proto.V1State_Ct1Sampled:
		c := v.Ct1Sampled
		uc := c.GetUc()
		if uc == nil {
			return nil, ErrV1StateDecode
		}
		enc, err := decEncoder(c.GetSendingCt1())
		if err != nil {
			return nil, err
		}
		dec, err := decDecoder(c.GetReceivingEk())
		if err != nil {
			return nil, err
		}
		return &v1State{
			tag: tagCt1Sampled, epoch: uc.GetEpoch(), auth: authFrom(uc.GetAuth()),
			hdr: uc.GetHdr(), es: uc.GetEs(), ct1: uc.GetCt1(),
			sendingCt1: enc, recvingEk: dec,
		}, nil

	case *proto.V1State_EkReceivedCt1Sampled:
		c := v.EkReceivedCt1Sampled
		uc := c.GetUc()
		if uc == nil {
			return nil, ErrV1StateDecode
		}
		enc, err := decEncoder(c.GetSendingCt1())
		if err != nil {
			return nil, err
		}
		return &v1State{
			tag: tagEkReceivedCt1Sampled, epoch: uc.GetEpoch(), auth: authFrom(uc.GetAuth()),
			es: uc.GetEs(), ek: uc.GetEk(), ct1: uc.GetCt1(), sendingCt1: enc,
		}, nil

	case *proto.V1State_Ct1Acknowledged:
		c := v.Ct1Acknowledged
		uc := c.GetUc()
		if uc == nil {
			return nil, ErrV1StateDecode
		}
		dec, err := decDecoder(c.GetReceivingEk())
		if err != nil {
			return nil, err
		}
		return &v1State{
			tag: tagCt1Acknowledged, epoch: uc.GetEpoch(), auth: authFrom(uc.GetAuth()),
			hdr: uc.GetHdr(), es: uc.GetEs(), ct1: uc.GetCt1(), recvingEk: dec,
		}, nil

	case *proto.V1State_Ct2Sampled:
		c := v.Ct2Sampled
		uc := c.GetUc()
		if uc == nil {
			return nil, ErrV1StateDecode
		}
		enc, err := decEncoder(c.GetSendingCt2())
		if err != nil {
			return nil, err
		}
		return &v1State{
			tag: tagCt2Sampled, epoch: uc.GetEpoch(), auth: authFrom(uc.GetAuth()), sendingCt2: enc,
		}, nil

	default:
		return nil, ErrV1StateDecode
	}
}

// authFrom builds an authenticator from its proto (nil tolerated → zero auth,
// matching the generated getter's nil handling).
func authFrom(pb *proto.Authenticator) *authenticator {
	return authenticatorFromProto(pb)
}

// decEncoder reconstructs a chunked Encoder from its proto, requiring it present.
func decEncoder(pb *proto.PolynomialEncoder) (*chunked.Encoder, error) {
	if pb == nil {
		return nil, fmt.Errorf("%w: missing encoder", ErrV1StateDecode)
	}
	enc, err := chunked.EncoderFromProto(pb)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrV1StateDecode, err)
	}
	return enc, nil
}

// decDecoder reconstructs a chunked Decoder from its proto, requiring it present.
func decDecoder(pb *proto.PolynomialDecoder) (*chunked.Decoder, error) {
	if pb == nil {
		return nil, fmt.Errorf("%w: missing decoder", ErrV1StateDecode)
	}
	dec, err := chunked.DecoderFromProto(pb)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrV1StateDecode, err)
	}
	return dec, nil
}
