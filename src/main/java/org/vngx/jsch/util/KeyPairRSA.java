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

import org.vngx.jsch.algorithm.KeyPairGenRSA;
import org.vngx.jsch.Buffer;
import org.vngx.jsch.Util;
import org.vngx.jsch.config.JSchConfig;
import org.vngx.jsch.algorithm.Algorithms;
import org.vngx.jsch.exception.JSchException;

/**
 * Implementation of <code>KeyPair</code> for generating a public/private key
 * pair using RSA encryption.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public class KeyPairRSA extends KeyPair {

	/** Constant begin line for RSA private key file. */
	private static final byte[] BEGIN = Util.str2byte("-----BEGIN RSA PRIVATE KEY-----");
	/** Constant end line for RSA private key file. */
	private static final byte[] END = Util.str2byte("-----END RSA PRIVATE KEY-----");

	/** Key size used for generating key. */
	private int _keySize = 1024;
	/** Private key value. */
	private byte[] _prvKey;
	/** Public key value. */
	private byte[] _pubKey;
	/** Modulus 'n' calculated from (p * q). */
	private byte[] _n;
	/** Prime number p. */
	private byte[] _p;
	/** Prime number q. */
	private byte[] _q;
	/** Prime exponent p. */
	private byte[] _ep;
	/** Prime exponent q. */
	private byte[] _eq;
	/** Coefficient value. */
	private byte[] _c;
	

	/**
	 * Creates a new instance of <code>KeyPairRSA</code>.
	 */
	public KeyPairRSA() { }

	@Override
	void generate(int keySize) throws JSchException {
		try {
			KeyPairGenRSA keypairgen = JSchConfig.getConfig().getClassImpl(Algorithms.KEYPAIRGEN_RSA);
			keypairgen.init(_keySize = keySize);	// Initialize generator with key size
			_pubKey = keypairgen.getE();
			_prvKey = keypairgen.getD();
			_n = keypairgen.getN();
			_p = keypairgen.getP();
			_q = keypairgen.getQ();
			_ep = keypairgen.getEP();
			_eq = keypairgen.getEQ();
			_c = keypairgen.getC();
		} catch(Exception e) {
			throw new JSchException("Failed to generate KeyPairRSA: "+e, e);
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
				1 + DataUtil.countLength(_n.length) + _n.length +			// INTEGER  N
				1 + DataUtil.countLength(_pubKey.length) + _pubKey.length +	// INTEGER  pub
				1 + DataUtil.countLength(_prvKey.length) + _prvKey.length +	// INTEGER  prv
				1 + DataUtil.countLength(_p.length) + _p.length +			// INTEGER  p
				1 + DataUtil.countLength(_q.length) + _q.length +			// INTEGER  q
				1 + DataUtil.countLength(_ep.length) + _ep.length +			// INTEGER  ep
				1 + DataUtil.countLength(_eq.length) + _eq.length +			// INTEGER  eq
				1 + DataUtil.countLength(_c.length) + _c.length;			// INTEGER  c
		int total = 1 + DataUtil.countLength(content) + content;			// SEQUENCE

		byte[] plain = new byte[total];
		int index = 0;
		index = DataUtil.writeSEQUENCE(plain, index, content);
		index = DataUtil.writeINTEGER(plain, index, new byte[1]);  // 0
		index = DataUtil.writeINTEGER(plain, index, _n);
		index = DataUtil.writeINTEGER(plain, index, _pubKey);
		index = DataUtil.writeINTEGER(plain, index, _prvKey);
		index = DataUtil.writeINTEGER(plain, index, _p);
		index = DataUtil.writeINTEGER(plain, index, _q);
		index = DataUtil.writeINTEGER(plain, index, _ep);
		index = DataUtil.writeINTEGER(plain, index, _eq);
		index = DataUtil.writeINTEGER(plain, index, _c);
		return plain;
	}

	@Override
	boolean parse(byte[] plain) {
		try {
			int[] index = new int[1];
			int length = 0;

			if( _vendor == VENDOR_FSECURE ) {
				if( plain[index[0]] != 0x30 ) {                  // FSecure
					Buffer buf = new Buffer(plain);
					_pubKey = buf.getMPIntBits();
					_prvKey = buf.getMPIntBits();
					_n = buf.getMPIntBits();
					buf.getMPIntBits();	// u array?
					_p = buf.getMPIntBits();
					_q = buf.getMPIntBits();
					return true;
				}
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
			if( plain[index[0]] != 0x02 ) {
				return false;
			}

			DataUtil.readINTEGER(index, plain);
			_n		= DataUtil.readINTEGER(index, plain);
			_pubKey = DataUtil.readINTEGER(index, plain);
			_prvKey = DataUtil.readINTEGER(index, plain);
			_p		= DataUtil.readINTEGER(index, plain);
			_q		= DataUtil.readINTEGER(index, plain);
			_ep		= DataUtil.readINTEGER(index, plain);
			_eq		= DataUtil.readINTEGER(index, plain);
			_c		= DataUtil.readINTEGER(index, plain);
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
		} else if( _pubKey == null ) {
			return null;
		}

		byte[] buffer = new byte[KeyType.SSH_RSA.toString().length() + 4 +
				_pubKey.length + 4 + _n.length + 4];
		Buffer buf = new Buffer(buffer);
		buf.putString(KeyType.SSH_RSA.getBytes());
		buf.putString(_pubKey);
		buf.putString(_n);
		return buffer;
	}

	@Override
	byte[] getKeyTypeName() {
		return KeyType.SSH_RSA.getBytes();
	}

	@Override
	int getKeySize() {
		return _keySize;
	}

	@Override
	public KeyType getKeyType() {
		return KeyType.SSH_RSA;
	}

	@Override
	public void dispose() {
		super.dispose();
		Util.bzero(_prvKey);
	}

}
