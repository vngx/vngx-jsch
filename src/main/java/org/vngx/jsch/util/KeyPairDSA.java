/*
 * Copyright (c) 2002-2010 Atsuhiko Yamanaka, JCraft,Inc.  All rights reserved.
 * Copyright (c) 2010-2011 Michael Laudati, N1 Concepts LLC.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. The names of the authors may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
 * INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.vngx.jsch.util;

import org.vngx.jsch.algorithm.KeyPairGenDSA;
import org.vngx.jsch.Buffer;
import org.vngx.jsch.Util;
import org.vngx.jsch.config.JSchConfig;
import org.vngx.jsch.algorithm.Algorithms;
import org.vngx.jsch.exception.JSchException;

/**
 * Implementation of <code>KeyPair</code> for generating a public/private key
 * pair using DSA encryption.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public class KeyPairDSA extends KeyPair {

	/** Constant begin line for DSA private key file. */
	private static final byte[] BEGIN = Util.str2byte("-----BEGIN DSA PRIVATE KEY-----");
	/** Constant end line for DSA private key file. */
	private static final byte[] END = Util.str2byte("-----END DSA PRIVATE KEY-----");

	/** Key size to generate. */
	private int _keySize = 1024;
	/** Public key data */
	private byte[] _pubKey;
	/** Private key data */
	private byte[] _prvKey;
	/** DSA prime modulus 'p'. */
	private byte[] _p;
	/** DSA prime number 'q'. */
	private byte[] _q;
	/** DSA number whose multiplicative order modulo p is q. */
	private byte[] _g;
	

	/**
	 * Creates a new instance of <code>KeyPairDSA</code>.
	 */
	public KeyPairDSA() { }

	@Override
	void generate(int keySize) throws JSchException {
		try {
			KeyPairGenDSA keypairgen = JSchConfig.getConfig().getClassImpl(Algorithms.KEYPAIRGEN_DSA);
			keypairgen.init(_keySize = keySize);	// Initialize generator with key size
			_pubKey = keypairgen.getY();
			_prvKey = keypairgen.getX();
			_p = keypairgen.getP();
			_q = keypairgen.getQ();
			_g = keypairgen.getG();
		} catch(Exception e) {
			throw new JSchException("Failed to generate KeyPairDSA: "+e, e);
		}
	}

	@Override
	byte[] getBegin() {
		return BEGIN;
	}

	@Override
	byte[] getEnd() {
		return END;
	}

	@Override
	byte[] getPrivateKey() {
		int content =
				1 + DataUtil.countLength(1) + 1 +							// INTEGER
				1 + DataUtil.countLength(_p.length) + _p.length +			// INTEGER  P
				1 + DataUtil.countLength(_q.length) + _q.length +			// INTEGER  Q
				1 + DataUtil.countLength(_g.length) + _g.length +			// INTEGER  G
				1 + DataUtil.countLength(_pubKey.length) + _pubKey.length +	// INTEGER  pub
				1 + DataUtil.countLength(_prvKey.length) + _prvKey.length;	// INTEGER  prv
		int total = 1 + DataUtil.countLength(content) + content;			// SEQUENCE

		byte[] plain = new byte[total];
		int index = 0;
		index = DataUtil.writeSEQUENCE(plain, index, content);
		index = DataUtil.writeINTEGER(plain, index, new byte[1]);  // 0
		index = DataUtil.writeINTEGER(plain, index, _p);
		index = DataUtil.writeINTEGER(plain, index, _q);
		index = DataUtil.writeINTEGER(plain, index, _g);
		index = DataUtil.writeINTEGER(plain, index, _pubKey);
		index = DataUtil.writeINTEGER(plain, index, _prvKey);
		return plain;
	}

	@Override
	boolean parse(byte[] plain) {
		try {
			if( _vendor == VENDOR_FSECURE ) {
				if( plain[0] != 0x30 ) {              // FSecure
					Buffer buf = new Buffer(plain);
					buf.getInt();
					_p = buf.getMPIntBits();
					_g = buf.getMPIntBits();
					_q = buf.getMPIntBits();
					_pubKey = buf.getMPIntBits();
					_prvKey = buf.getMPIntBits();
					return true;
				}
				return false;
			}

			int[] index = new int[1];
			int length = 0;
			if( plain[index[0]] != 0x30 ) {	// Zero '0'
				return false;
			}
			index[0]++; // SEQUENCE
			length = plain[index[0]++] & 0xff;
			if( (length & 0x80) != 0 ) {
				int foo = length & 0x7f;
				length = 0;
				while( foo-- > 0 ) {
					length = (length << 8) + (plain[index[0]++] & 0xff);
				}
			}
			if( plain[index[0]] != 0x02 ) {	// STX (start of text)
				return false;
			}

			DataUtil.readINTEGER(index, plain);
			_p		= DataUtil.readINTEGER(index, plain);
			_q		= DataUtil.readINTEGER(index, plain);
			_g		= DataUtil.readINTEGER(index, plain);
			_pubKey = DataUtil.readINTEGER(index, plain);
			_prvKey = DataUtil.readINTEGER(index, plain);
		} catch(Exception e) {
			// TODO Error handling?
			return false;
		}
		return true;
	}

	@Override
	public byte[] getPublicKeyBlob() {
		byte[] pubKeyBlob = super.getPublicKeyBlob();
		if( pubKeyBlob != null ) {
			return pubKeyBlob;
		} else if( _p == null ) {
			return null;
		}

		byte[] buffer = new byte[KeyType.SSH_DSS.toString().length() + 4 + _p.length + 4 +
				_q.length + 4 + _g.length + 4 + _pubKey.length + 4];
		Buffer buf = new Buffer(buffer);
		buf.putString(KeyType.SSH_DSS.getBytes());
		buf.putString(_p);
		buf.putString(_q);
		buf.putString(_g);
		buf.putString(_pubKey);
		return buffer;
	}

	@Override
	byte[] getKeyTypeName() {
		return KeyType.SSH_DSS.getBytes();
	}

	@Override
	int getKeySize() {
		return _keySize;
	}

	@Override
	public KeyType getKeyType() {
		return KeyType.SSH_DSS;
	}

	@Override
	public void dispose() {
		super.dispose();
		Util.bzero(_prvKey);
	}

}
