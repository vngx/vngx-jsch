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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import org.vngx.jsch.config.JSchConfig;

/**
 * <p>Implementation of {@code MAC} (Message Authentication Code) using the
 * implementations provided by JCE. The security provider for creating instances
 * is set with the {@code JSchConfig} property defined as
 * {@link org.vngx.jsch.config.JSchConfig#DEFAULT_SECURITY_PROVIDER}; by
 * default the default security provider will be used. If another security
 * provider has been registered, then the security provider name in the
 * configuration will be used when creating instances.</p>
 *
 * @see javax.crypto.Mac
 * @see org.vngx.jsch.hash.MAC
 * @see org.vngx.jsch.config.JSchConfig
 * @see org.vngx.jsch.config.JSchConfig#DEFAULT_SECURITY_PROVIDER
 *
 * @author Michael Laudati
 */
public class MACImpl implements MAC {

	/** Block size of MAC. */
	private final int _blockSize;
	/** Message authentication code instance from JCE library. */
	private final Mac _mac;

	
	/**
	 * Creates a new instance of {@code MACImpl} which uses the specified Java
	 * JCE MAC implementation name to create the {@code Mac} instance and uses
	 * the specified block size.
	 *
	 * @param macName (MAC algorithm name)
	 * @param blockSize
	 * @throws NoSuchAlgorithmException if specified algorithm does not exist
	 * @throws NoSuchProviderException 
	 */
	protected MACImpl(String macName, int blockSize) throws NoSuchAlgorithmException, NoSuchProviderException {
		String provider = JSchConfig.getConfig().getString(JSchConfig.DEFAULT_SECURITY_PROVIDER);
		_mac = provider.isEmpty() ? Mac.getInstance(macName) : Mac.getInstance(macName, provider);
		_blockSize = blockSize;
	}

	@Override
	public void init(byte[] key) throws MACException {
		if( key.length > _blockSize ) {
			key = Arrays.copyOf(key, _blockSize);
		}
		try {
			_mac.init(new SecretKeySpec(key, _mac.getAlgorithm()));
		} catch(InvalidKeyException ike) {
			throw new MACException("Failed to initialize MAC", ike);
		}
	}

	@Override
	public void update(int value) {
		_mac.update((byte) (value >>> 24));
		_mac.update((byte) (value >>> 16));
		_mac.update((byte) (value >>> 8));
		_mac.update((byte) value);
	}

	@Override
	public void update(byte[] buffer, int offset, int length) {
		_mac.update(buffer, offset, length);
	}

	@Override
	public void doFinal(byte[] buffer, int offset) throws MACException {
		try {
			_mac.doFinal(buffer, offset);
		} catch(ShortBufferException e) {
			throw new MACException("Failed to generate MAC digest", e);
		}
	}

	@Override
	public int getBlockSize() {
		return _blockSize;
	}

	/**
	 * Implementation of {@code MAC} using MD5 for the hash.
	 *
	 * @author Michael Laudati
	 */
	public static class HMAC_MD5 extends MACImpl {
		/**
		 * Creates a new instance of {@code HMAC_MD5}.
		 *
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException
		 */
		public HMAC_MD5() throws NoSuchAlgorithmException, NoSuchProviderException {
			super("HmacMD5", 16);
		}
	}

	/**
	 * Implementation of {@code MAC} using the first 96 bits of MD5 hash.
	 *
	 * @author Michael Laudati
	 */
	public static class HMAC_MD5_96 extends MACImpl {
		/** Temporary buffer for copying during doFinal(). */
		private final byte[] _buf16 = new byte[16];

		/**
		 * Creates a new instance of {@code HMAC_MD5_96}.
		 *
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException
		 */
		public HMAC_MD5_96() throws NoSuchAlgorithmException, NoSuchProviderException {
			super("HmacMD5", 16);
		}

		@Override
		public int getBlockSize() {
			return 12;
		}

		@Override
		public void doFinal(byte[] buffer, int offset) throws MACException {
			super.doFinal(_buf16, 0);
			System.arraycopy(_buf16, 0, buffer, offset, 12);
		}
	}

	/**
	 * Implementation of {@code MAC} using SHA-1 for the hash.
	 *
	 * @author Michael Laudati
	 */
	public static class HMAC_SHA1 extends MACImpl {
		/**
		 * Creates a new instance of {@code HMAC_SHA1}.
		 *
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException
		 */
		public HMAC_SHA1() throws NoSuchAlgorithmException, NoSuchProviderException {
			super("HmacSHA1", 20);
		}
	}

	/**
	 * Implementation of {@code MAC} using the first 96 bits of SHA-1 hash.
	 *
	 * @author Michael Laudati
	 */
	public static class HMAC_SHA1_96 extends MACImpl {
		/** Temporary buffer for copying in doFinal(). */
		private final byte[] _buf20 = new byte[20];

		/**
		 * Creates a new instance of {@code HMAC_SHA1_96}.
		 *
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException
		 */
		public HMAC_SHA1_96() throws NoSuchAlgorithmException, NoSuchProviderException {
			super("HmacSHA1", 20);
		}

		@Override
		public int getBlockSize() {
			return 12;
		}

		@Override
		public void doFinal(byte[] buffer, int offset) throws MACException {
			super.doFinal(_buf20, 0);
			System.arraycopy(_buf20, 0, buffer, offset, 12);
		}
	}

	/**
	 * Implementation of {@code MAC} using the SHA-256 hash.
	 * 
	 * @author Michael Laudati
	 */
	public static class HMAC_SHA_256 extends MACImpl {
		/**
		 * Creates a new instance of {@code HMAC_SHA_256}.
		 *
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException 
		 */
		public HMAC_SHA_256() throws NoSuchAlgorithmException, NoSuchProviderException {
			super("HmacSHA256", 32);
		}
	}

}
