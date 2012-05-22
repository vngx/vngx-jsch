/*
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
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL N1
 * CONCEPTS LLC OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.vngx.jsch.hash;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.vngx.jsch.Util;
import org.vngx.jsch.config.JSchConfig;

/**
 * <p>Implementation of {@code MAC} algorithm (Message Authentication Code),
 * provided as an alternative to Java's built in MAC implementations through
 * JCE.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc2104">RFC 2104 - HMAC: Keyed-
 * Hashing for Message Authentication</a></p>
 *
 * <p><pre>
 * H(K XOR opad, H(K XOR ipad, text))
 *
 * where K is an n byte key
 * ipad is the byte 0x36 repeated 64 times
 * opad is the byte 0x5c repeated 64 times
 * and text is the data being protected
 * </pre></p>
 *
 * @see java.security.MessageDigest;
 * @see org.vngx.jsch.hash.MAC
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public abstract class MACImplAlternate implements MAC {

	/* Constant size for padding buffers. */
	private static final int B = 64;

	/** Hash function to use for MAC. */
	private final MessageDigest _md;
	/** Block size of hash function. */
	private final int _blockSize;

	/** Inner padding block. */
	private byte[] _kInnerPad;
	/** Outter padding block. */
	private byte[] _kOuterPad;
	/** Temporary buffer to use when updating. */
	private final byte[] _tmp = new byte[4];

	
	/**
	 * Creates a new instance of {@code MAC} which uses the specified message
	 * digest algorithm.
	 *
	 * @param messageDigest to get instance from JCE library
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException 
	 */
	protected MACImplAlternate(String messageDigest) throws NoSuchAlgorithmException, NoSuchProviderException {
		String provider = JSchConfig.getConfig().getString(JSchConfig.DEFAULT_SECURITY_PROVIDER);
		_md = provider.length()==0 ? MessageDigest.getInstance(messageDigest) :
									MessageDigest.getInstance(messageDigest, provider);
		_blockSize = _md.getDigestLength();
	}

	@Override
	public int getBlockSize() {
		return _blockSize;
	}

	@Override
	public void init(byte[] key) {
		// If key size greater than block size, truncate key to block size length
		if( key.length > _blockSize ) {
			key = Util.copyOf(key, _blockSize);
		}
		// if key is longer than B bytes reset it to key=Hash(key)
		if( key.length > B ) {
			_md.update(key, 0, key.length);
			key = _md.digest();
		}
		_kInnerPad = Util.copyOf(key, B);
		_kOuterPad = Util.copyOf(key, B);

		// XOR key with ipad and opad values
		for( int i = 0; i < B; i++ ) {
			_kInnerPad[i] ^= (byte) 0x36;
			_kOuterPad[i] ^= (byte) 0x5c;
		}
		_md.update(_kInnerPad, 0, B);
	}

	@Override
	public void update(int i) {
		_tmp[0] = (byte) (i >>> 24);
		_tmp[1] = (byte) (i >>> 16);
		_tmp[2] = (byte) (i >>> 8);
		_tmp[3] = (byte) i;
		update(_tmp, 0, 4);
	}

	@Override
	public void update(byte[] buffer, int offset, int length) {
		_md.update(buffer, offset, length);
	}

	@Override
	public void doFinal(byte[] buffer, int offset) throws MACException {
		byte[] result = _md.digest();
		_md.update(_kOuterPad, 0, B);
		_md.update(result, 0, _blockSize);
		try {
			_md.digest(buffer, offset, _blockSize);
		} catch(DigestException e) {
			throw new MACException("Failed to generate MAC digest", e);
		}
		_md.update(_kInnerPad, 0, B);
	}

	/**
	 * Implementation of {@code MAC} using MD5 for the hash.
	 *
	 * @author Michael Laudati
	 */
	public static class HMAC_MD5 extends MACImplAlternate {
		/**
		 * Creates a new instance of {@code HMAC_MD5}.
		 *
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException
		 */
		public HMAC_MD5() throws NoSuchAlgorithmException, NoSuchProviderException {
			super("MD5");
		}
	}

	/**
	 * Implementation of {@code MAC} using MD5 with a block size of 12.
	 *
	 * @author Michael Laudati
	 */
	public static class HMAC_MD5_96 extends MACImplAlternate {
		/** Constant for block size. */
		private static final int BLOCK_SIZE = 12;
		/** Temporary buffer used when calling doFinal(). */
		private final byte[] _buf16 = new byte[16];

		/**
		 * Creates a new instance of {@code HMAC_MD5_96}.
		 *
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException
		 */
		public HMAC_MD5_96() throws NoSuchAlgorithmException, NoSuchProviderException {
			super("MD5");
		}

		@Override
		public int getBlockSize() {
			return BLOCK_SIZE;
		}

		@Override
		public void doFinal(byte[] buffer, int offset) throws MACException {
			super.doFinal(_buf16, 0);
			System.arraycopy(_buf16, 0, buffer, offset, BLOCK_SIZE);
		}
	}

	/**
	 * Implementation of {@code MAC} using SHA-1 hash.
	 *
	 * @author Michael Laudati
	 */
	public static class HMAC_SHA1 extends MACImplAlternate {
		/**
		 * Creates a new instance of {@code HMAC_SHA1}.
		 *
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException
		 */
		public HMAC_SHA1() throws NoSuchAlgorithmException, NoSuchProviderException {
			super("SHA-1");
		}
	}

	 /**
	 * Implementation of {@code MAC} using SHA1 hash and a block size of
	 * 12.
	 *
	 * @author Michael Laudati
	 */
	public static class HMAC_SHA1_96 extends MACImplAlternate {
		/** Constant block size. */
		private static final int BLOCK_SIZE = 12;
		/** Temporary buffer when running doFinal(). */
		private final byte[] _buf20 = new byte[20];

		/**
		 * Creates a new instance of {@code HMAC_SHA1_96}.
		 *
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException
		 */
		public HMAC_SHA1_96() throws NoSuchAlgorithmException, NoSuchProviderException {
			super("SHA-1");
		}

		@Override
		public int getBlockSize() {
			return BLOCK_SIZE;
		}

		@Override
		public void doFinal(byte[] buffer, int offset) throws MACException {
			super.doFinal(_buf20, 0);
			System.arraycopy(_buf20, 0, buffer, offset, BLOCK_SIZE);
		}
	}

	/**
	 * Implementation of {@code MAC} using SHA-256 hash.
	 *
	 * @author Michael Laudati
	 */
	public static class HMAC_SHA_256 extends MACImplAlternate {
		/**
		 * Creates a new instance of {@code HMAC_SHA_256}.
		 *
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException 
		 */
		public HMAC_SHA_256() throws NoSuchAlgorithmException, NoSuchProviderException {
			super("SHA-256");
		}
	}

}
