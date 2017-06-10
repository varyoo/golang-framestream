/*
 * Copyright (c) 2014 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package framestream

import "bufio"
import "encoding/binary"
import "io"

type EncoderOptions struct {
	ContentType []byte
}

type Encoder struct {
	writer *bufio.Writer
	opt    EncoderOptions
	buf    []byte
}

func NewBiEncoder(rw io.ReadWriter, opt *EncoderOptions) (enc *Encoder, err error) {
	writer := bufio.NewWriter(rw)

	// Write the ready control frame.
	cf := &ControlFrame{ControlType: CONTROL_READY}
	if opt.ContentType != nil {
		cf.ContentTypes = [][]byte{enc.opt.ContentType}
	}
	if err = SendControlFrame(writer, cf); err != nil {
		return
	}

	// Wait for the accept frame.
	cf, err = ReadControlFrame(rw)
	if err != nil {
		return
	}

	// Check content type.
	matched := MatchContentTypes(cf.ContentTypes, [][]byte{opt.ContentType})
	if len(matched) != 1 {
		return enc, ErrContentTypeMismatch
	}

	return NewEncoder(rw, opt)
}

func NewEncoder(w io.Writer, opt *EncoderOptions) (enc *Encoder, err error) {
	if opt == nil {
		opt = &EncoderOptions{}
	}
	enc = &Encoder{
		writer: bufio.NewWriter(w),
		opt:    *opt,
	}

	// Write the start control frame.
	err = enc.writeControlStart()
	if err != nil {
		return
	}

	return
}

func (enc *Encoder) Close() error {
	return enc.writeControlStop()
}

func (enc *Encoder) writeControlStart() (err error) {
	cf := ControlFrame{ControlType: CONTROL_START}
	if enc.opt.ContentType != nil {
		cf.ContentTypes = [][]byte{enc.opt.ContentType}
	}
	return SendControlFrame(enc.writer, &cf)
}

func (enc *Encoder) writeControlStop() (err error) {
	cf := ControlFrame{ControlType: CONTROL_STOP}
	return SendControlFrame(enc.writer, &cf)
}

func (enc *Encoder) Write(frame []byte) (n int, err error) {
	err = binary.Write(enc.writer, binary.BigEndian, uint32(len(frame)))
	if err != nil {
		return
	}
	return enc.writer.Write(frame)
}

func (enc *Encoder) Flush() error {
	return enc.writer.Flush()
}
