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

package org.vngx.jsch.cipher;

import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.vngx.jsch.config.JSchConfig;

/**
 * <p>Implementation of {@code Cipher} which wraps a {@code javax.crypto.Cipher}
 * instance from Java's JCE.  The security provider for creating instances is
 * set with the {@code JSchConfig} property defined as 
 * {@link org.vngx.jsch.config.JSchConfig#DEFAULT_SECURITY_PROVIDER}; by
 * default the default security provider will be used. If another security
 * provider has been registered, then the security provider name in the
 * configuration will be used when creating instances.</p>
 *
 * <p><a href="http://download.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html">
 * Java ™ Cryptography Architecture (JCA) Reference Guide</a></p>
 *
 * @see javax.crypto.Cipher
 * @see org.vngx.jsch.cipher.Cipher
 * @see org.vngx.jsch.cipher.CipherManager
 * @see org.vngx.jsch.config.JSchConfig
 * @see org.vngx.jsch.config.JSchConfig#DEFAULT_SECURITY_PROVIDER
 *
 * @author Michael Laudati
 */
public class CipherImpl implements Cipher {

	/** Name of cipher to create. */
	final String _cipherName;
	/** Name of key to create. */
	final String _keyName;
	/** Initialization vector size for cipher. */
	final int _ivSize;
	/** Block size for cipher. */
	final int _blockSize;
	/** True if the cipher uses cipher-block chaining mode of operation. */
	final boolean _cbc;

	/** Wrapped JCE cipher instance .*/
	javax.crypto.Cipher _cipher;


	/**
	 * Creates a new instance of {@code JCECipher} with the specified
	 * cipher name, key name, initialization vector and block size.
	 * 
	 * @param cipherName (JCE name for retrieving instance)
	 * @param keyName
	 * @param ivSize in bytes
	 * @param blockSize in bytes
	 * @param cbc (true if cipher uses cipher-block chaining mode of operation)
	 */
	protected CipherImpl(String cipherName, String keyName, int ivSize, int blockSize, boolean cbc) {
		_cipherName = cipherName;
		_keyName = keyName;
		_ivSize = ivSize;
		_blockSize = blockSize;
		_cbc = cbc;
	}

	@Override
	public int getIVSize() {
		return _ivSize;
	}

	@Override
	public int getBlockSize() {
		return _blockSize;
	}

	@Override
	public boolean isCBC() {
		return _cbc;
	}

	@Override
	public void init(int mode, byte[] key, byte[] iv) throws CipherException {
		iv = validateIVSize(iv);	// Update IV size if too large
		key = validateKeySize(key);	// Update key size if too large
		try {
			// Retrieve cipher instance based on JCE provider specified in CipherManager
			_cipher = JSchConfig.getConfig().getString(JSchConfig.DEFAULT_SECURITY_PROVIDER).isEmpty() ?
						javax.crypto.Cipher.getInstance(_cipherName) :
						javax.crypto.Cipher.getInstance(_cipherName, 
								JSchConfig.getConfig().getString(JSchConfig.DEFAULT_SECURITY_PROVIDER));
			_cipher.init(mode, new SecretKeySpec(key, _keyName), new IvParameterSpec(iv));
		} catch(Exception e) {
			_cipher = null;
			throw new CipherException("Failed to initialize cipher", e);
		}
	}

	@Override
	public void update(byte[] src, int srcOffset, int length, byte[] dest, int destOffset) throws CipherException {
		try {
			_cipher.update(src, srcOffset, length, dest, destOffset);
		} catch(ShortBufferException e) {
			throw new CipherException("Failed to update cipher", e);
		}
	}

	/**
	 * Validates the key size by truncating the key value to the block size if
	 * and only if the key size is greater than the block size.
	 *
	 * @param key
	 * @return validated key
	 */
	byte[] validateKeySize(byte[] key) {
		return key.length > _blockSize ? Arrays.copyOf(key, _blockSize) : key;
	}

	/**
	 * Validates the IV size by truncating the IV value to the IV size if and
	 * only if the specified IV is greater than the IV size.
	 *
	 * @param iv
	 * @return validated IV
	 */
	byte[] validateIVSize(byte[] iv) {
		return iv.length > _ivSize ? Arrays.copyOf(iv, _ivSize) : iv;
	}

	/**
	 * Implementation of {@code Cipher} for aes-128-cbc cipher.
	 *
	 * @author Michael Laudati
	 */
	public static class AES128CBC extends CipherImpl {
		/**
		 * Creates a new instance of {@code AES128CBC}.
		 */
		public AES128CBC() {
			super("AES/CBC/NoPadding", "AES", 16, 16, true);
		}
	}

	/**
	 * Implementation of {@code Cipher} for aes-128-ctr cipher.
	 *
	 * @author Michael Laudati
	 */
	public static class AES128CTR extends CipherImpl {
		/**
		 * Creates a new instance of {@code AES128CTR}.
		 */
		public AES128CTR() {
			super("AES/CTR/NoPadding", "AES", 16, 16, false);
		}
	}

	/**
	 * Implementation of {@code Cipher} for aes-192-cbc cipher.
	 *
	 * @author Michael Laudati
	 */
	public static class AES192CBC extends CipherImpl {
		/**
		 * Creates a new instance of {@code AES192CBC}.
		 */
		public AES192CBC() {
			super("AES/CBC/NoPadding", "AES", 16, 24, true);
		}
	}

	/**
	 * Implementation of {@code Cipher} for aes-192-ctr cipher.
	 *
	 * @author Michael Laudati
	 */
	public static class AES192CTR extends CipherImpl {
		/**
		 * Creates a new instance of {@code AES192CBC}.
		 */
		public AES192CTR() {
			super("AES/CTR/NoPadding", "AES", 16, 24, false);
		}
	}

	/**
	 * Implementation of {@code Cipher} for aes-256-cbc cipher.
	 *
	 * @author Michael Laudati
	 */
	public static class AES256CBC extends CipherImpl {
		/**
		 * Creates a new instance of {@code AES256CBC}.
		 */
		public AES256CBC() {
			super("AES/CBC/NoPadding", "AES", 16, 32, true);
		}
	}

	/**
	 * Implementation of {@code Cipher} for aes-256-ctr cipher.
	 *
	 * @author Michael Laudati
	 */
	public static class AES256CTR extends CipherImpl {
		/**
		 * Creates a new instance of {@code AES256CTR}.
		 */
		public AES256CTR() {
			super("AES/CTR/NoPadding", "AES", 16, 32, false);
		}
	}

	/**
	 * Implementation of {@code Cipher} for arcfour (RC4) cipher.
	 *
	 * @author Michael Laudati
	 */
	public static class ARCFOUR extends CipherImpl {
		ARCFOUR(String cipherName, String keyName, int ivSize, int blockSize, boolean cbc) {
			super(cipherName, keyName, ivSize, blockSize, cbc);
		}

		/**
		 * Creates a new instance of {@code ARCFOUR}.
		 */
		public ARCFOUR() {
			super("RC4", "RC4", 8, 16, false);
		}

		@Override
		public void init(int mode, byte[] key, byte[] iv) throws CipherException {
			key = validateKeySize(key);
			try {
				// Retrieve cipher instance based on JCE provider specified in CipherManager
				_cipher = JSchConfig.getConfig().getString(JSchConfig.DEFAULT_SECURITY_PROVIDER).isEmpty() ?
						javax.crypto.Cipher.getInstance(_cipherName) :
						javax.crypto.Cipher.getInstance(_cipherName,
								JSchConfig.getConfig().getString(JSchConfig.DEFAULT_SECURITY_PROVIDER));
				_cipher.init(mode, new SecretKeySpec(key, _keyName));
			} catch(Exception e) {
				_cipher = null;
				throw new CipherException("Failed to initialize cipher", e);
			}
		}
	}

	/**
	 * Implementation of {@code Cipher} for arcfour-128 cipher.
	 *
	 * @author Michael Laudati
	 */
	public static class ARCFOUR128 extends ARCFOUR {
		/** Constant amount to skip. */
		private static final int SKIP = 1536;

		ARCFOUR128(String cipherName, String keyName, int ivSize, int blockSize, boolean cbc) {
			super(cipherName, keyName, ivSize, blockSize, cbc);
		}

		/**
		 * Creates a new instance of {@code ARCFOUR128}.
		 */
		public ARCFOUR128() {
			super("RC4", "RC4", 8, 16, false);
		}

		@Override
		public void init(int mode, byte[] key, byte[] iv) throws CipherException {
			super.init(mode, key, iv);
			final byte[] tmp = new byte[1];
			for( int i = 0; i < SKIP; i++ ) {
				update(tmp, 0, 1, tmp, 0);
			}
		}
	}

	/**
	 * Implementation of {@code Cipher} for arcfour-256 cipher.
	 *
	 * @author Michael Laudati
	 */
	public static class ARCFOUR256 extends ARCFOUR128 {
		/**
		 * Creates a new instance of {@code ARCFOUR256}.
		 */
		public ARCFOUR256() {
			super("RC4", "RC4", 8, 32, false);
		}
	}

	/**
	 * Implementation of {@code Cipher} for blowfish-cbc cipher.
	 *
	 * @author Michael Laudati
	 */
	public static class BlowfishCBC extends CipherImpl {
		/**
		 * Creates a new instance of {@code BlowfishCBC}.
		 */
		public BlowfishCBC() {
			super("Blowfish/CBC/NoPadding", "Blowfish", 8, 16, true);
		}
	}

	/**
	 * Implementation of {@code Cipher} for 3des-cbc cipher.
	 *
	 * @author Michael Laudati
	 */
	public static class TripleDESCBC extends CipherImpl {
		/**
		 * Creates a new instance of {@code TripleDESCBC}.
		 */
		public TripleDESCBC() {
			this("DESede/CBC/NoPadding", true);
		}

		TripleDESCBC(String cipherName, boolean cbc) {
			super(cipherName, "DESede", 8, 24, cbc);
		}

		@Override
		public void init(int mode, byte[] key, byte[] iv) throws CipherException {
			iv = validateIVSize(iv);
			key = validateKeySize(key);
			try {
				// Retrieve cipher instance based on JCE provider specified in CipherManager
				_cipher = JSchConfig.getConfig().getString(JSchConfig.DEFAULT_SECURITY_PROVIDER).isEmpty() ?
						javax.crypto.Cipher.getInstance(_cipherName) :
						javax.crypto.Cipher.getInstance(_cipherName,
								JSchConfig.getConfig().getString(JSchConfig.DEFAULT_SECURITY_PROVIDER));
				/* The following code does not work on IBM's JDK 1.4.1
				SecretKeySpec skeySpec = new SecretKeySpec(key, "DESede");
				cipher.init(mode, skeySpec, new IvParameterSpec(iv));
				 */
				DESedeKeySpec keyspec = new DESedeKeySpec(key);
				SecretKey secretKey = SecretKeyFactory.getInstance(_keyName).generateSecret(keyspec);
				_cipher.init(mode, secretKey, new IvParameterSpec(iv));
			} catch(Exception e) {
				_cipher = null;
				throw new CipherException("Failed to initialize cipher", e);
			}
		}
	}

	/**
	 * Implementation of {@code Cipher} for 3des-ctr cipher.
	 *
	 * @author Michael Laudati
	 */
	public static class TripleDESCTR extends TripleDESCBC {
		/**
		 * Creates a new instance of {@code TripleDESCBC}.
		 */
		public TripleDESCTR() {
			super( "DESede/CTR/NoPadding", false);
		}
	}

}
