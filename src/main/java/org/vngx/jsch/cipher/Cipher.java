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

import org.vngx.jsch.algorithm.Algorithm;

/**
 * <p>{@code Cipher} defines an interface for an algorithm for performing
 * encryption or decryption.  Ciphers are used for encrypting/decrypting packets
 * sent with the SSH protocol.  The abstraction provided by this interface 
 * allows implementations to specify how the cipher should be implemented.</p>
 *
 * <p>An encryption algorithm and a key will be negotiated during the key
 * exchange.  When encryption is in effect, the packet length, padding length,
 * payload, and padding fields of each packet MUST be encrypted with the given
 * algorithm.</p>
 *
 * <p>The encrypted data in all packets sent in one direction SHOULD be
 * considered a single data stream.  For example, initialization vectors SHOULD
 * be passed from the end of one packet to the beginning of the next packet. All
 * ciphers SHOULD use keys with an effective key length of 128 bits or more.</p>
 *
 * <p>The ciphers in each direction MUST run independently of each other.
 * Implementations MUST allow the algorithm for each direction to be
 * independently selected, if multiple algorithms are allowed by local policy.
 * In practice however, it is RECOMMENDED that the same algorithm be used in
 * both directions.</p>
 *
 * <p>The following ciphers are defined in the SSH Transport Layer Protocol:
 * <pre>
 *	3des-cbc         REQUIRED          three-key 3DES in CBC mode
 *	blowfish-cbc     OPTIONAL          Blowfish in CBC mode
 *	twofish256-cbc   OPTIONAL          Twofish in CBC mode, with a 256-bit key
 * 	twofish-cbc      OPTIONAL          alias for "twofish256-cbc" (this is being retained for historical reasons)
 * 	twofish192-cbc   OPTIONAL          Twofish with a 192-bit key
 * 	twofish128-cbc   OPTIONAL          Twofish with a 128-bit key
 * 	aes256-cbc       OPTIONAL          AES in CBC mode, with a 256-bit key
 * 	aes192-cbc       OPTIONAL          AES with a 192-bit key
 * 	aes128-cbc       RECOMMENDED       AES with a 128-bit key
 * 	serpent256-cbc   OPTIONAL          Serpent in CBC mode, with a 256-bit key
 *	serpent192-cbc   OPTIONAL          Serpent with a 192-bit key
 * 	serpent128-cbc   OPTIONAL          Serpent with a 128-bit key
 * 	arcfour          OPTIONAL          the ARCFOUR stream cipher with a 128-bit key
 * 	idea-cbc         OPTIONAL          IDEA in CBC mode
 * 	cast128-cbc      OPTIONAL          CAST-128 in CBC mode
 * 	none             OPTIONAL          no encryption; NOT RECOMMENDED
 * </pre></p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253#section-6.3">RFC 4253 - The
 * Secure Shell (SSH) Transport Layer Protocol: Encryption</a></p>
 * <p><a href="http://tools.ietf.org/html/rfc4344">RFC 4344 - The Secure Shell
 * (SSH) Transport Layer Encryption Modes</a></p>
 *
 * <p><strong>Note:</strong> Implementations may not be thread-safe and should
 * be externally synchronized.</p>
 *
 * <p><strong>Note:</strong> Instances should be created using the
 * {@code CipherManager} factory.</p>
 *
 * @see org.vngx.jsch.cipher.CipherManager
 *
 * @author Michael Laudati
 */
public interface Cipher extends Algorithm {

	/**
	 * Algorithm name {@value} for {@code Cipher} providing no encryption.
	 */
	String CIPHER_NONE = "none";
	/** 
	 * Algorithm name {@value} for {@code Cipher} providing three-key 3DES in 
	 * CBC mode.
	 */
	String CIPHER_3DES_CBC = "3des-cbc";
	/**
	 * Algorithm name {@value} for {@code Cipher} providing three-key 3DES in
	 * CTR mode.
	 */
	String CIPHER_3DES_CTR = "3des-ctr";
	/**
	 * Algorithm name {@value} for {@code Cipher} providing Blowfish in CBC
	 * mode. 
	 */
	String CIPHER_BLOWFISH_CBC = "blowfish-cbc";
	/**
	 * Algorithm name {@value} for {@code Cipher} providing AES with a 128-bit
	 * key in CBC mode.
	 */
	String CIPHER_AES128_CBC = "aes128-cbc";
	/**
	 * Algorithm name {@value} for {@code Cipher} providing AES with a 192-bit
	 * key in CBC mode.
	 */
	String CIPHER_AES192_CBC = "aes192-cbc";
	/**
	 * Algorithm name {@value} for {@code Cipher} providing AES with a 256-bit
	 * key in CBC mode.
	 */
	String CIPHER_AES256_CBC = "aes256-cbc";
	/**
	 * Algorithm name {@value} for {@code Cipher} providing AES with a 128-bit
	 * key in CTR mode.
	 */
	String CIPHER_AES128_CTR = "aes128-ctr";
	/**
	 * Algorithm name {@value} for {@code Cipher} providing AES with a 196-bit
	 * key in CTR mode.
	 */
	String CIPHER_AES192_CTR = "aes192-ctr";
	/**
	 * Algorithm name {@value} for {@code Cipher} providing AES with a 256-bit
	 * key in CTR mode.
	 */
	String CIPHER_AES256_CTR = "aes256-ctr";
	/**
	 * Algorithm name {@value} for {@code Cipher} providing ARCFOUR stream
	 * cipher.
	 */
	String CIPHER_ARCFOUR = "arcfour";
	/**
	 * Algorithm name {@value} for {@code Cipher} providing ARCFOUR stream
	 * cipher with a 128-bit key.
	 */
	String CIPHER_ARCFOUR128 = "arcfour128";
	/**
	 * Algorithm name {@value} for {@code Cipher} providing ARCFOUR stream
	 * cipher with a 256-bit key.
	 */
	String CIPHER_ARCFOUR256 = "arcfour256";
	
	/** 
	 * Constant for encrypt mode (matches {@link javax.crypto.Cipher#ENCRYPT_MODE}
	 * for convenience).
	 */
	int ENCRYPT_MODE = javax.crypto.Cipher.ENCRYPT_MODE;
	/** 
	 * Constant for decrypt mode (matches {@link javax.crypto.Cipher#DECRYPT_MODE}
	 * for convenience).
	 */
	int DECRYPT_MODE = javax.crypto.Cipher.DECRYPT_MODE;

	/**
	 * <p>Returns the initialization vector size for cipher.</p>
	 *
	 * <p>An initialization vector (IV) is a block of bits that is required to
	 * allow a stream cipher or a block cipher to be executed to produce a
	 * unique stream independent from other streams produced by the same
	 * encryption key. The size of the IV depends on the encryption algorithm
	 * and on the cryptographic protocol in use and is normally as large as the
	 * block size of the cipher or as large as the encryption key.</p>
	 *
	 * @return initialization vector size
	 */
	int getIVSize();

	/**
	 * Returns the block size for the cipher.
	 *
	 * @return block size for cipher
	 */
	int getBlockSize();

	/**
	 * Returns true if the cipher uses the CBC (cipher-block chaining) mode of
	 * operation for encryption.
	 *
	 * @return true if CBC is mode of operation for cipher
	 */
	boolean isCBC();

	/**
	 * Initializes the cipher with the specified block mode, key and
	 * initialization vector.
	 *
	 * @param mode of operation for blocks
	 * @param key value
	 * @param iv initialization vector data
	 * @throws CipherException
	 */
	void init(int mode, byte[] key, byte[] iv) throws CipherException;

	/**
	 * Encrypts or decrypts (based on the mode set in {@code init()} method
	 * the specified buffer from the start position s1 through length and places
	 * the output in the specified destination at the start position s2.
	 * 
	 * @param buffer to encrypt/decrypt
	 * @param srcOffset start position in source
	 * @param length of source buffer to encrypt/decrypt
	 * @param dest destination buffer to receive output
	 * @param destOffset start position in destination
	 * @throws CipherException if any errors occur
	 */
	void update(byte[] buffer, int srcOffset, int length, byte[] dest, int destOffset) throws CipherException;

}
