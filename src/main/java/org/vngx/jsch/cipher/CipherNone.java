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

/**
 * <p>Empty implementation of {@code Cipher} to be used when no cipher is
 * required.  This should *ONLY* be used for debugging purposes... the RFC spec
 * for SSH strongly suggests that the client must notify the user whenever
 * CIPHER NONE is being used as data is being sent unencrypted.</p>
 *
 * <p>The "none" algorithm specifies that no encryption is to be done. Note that
 * this method provides no confidentiality protection and it is NOT RECOMMENDED.
 * Some functionality (e.g., password authentication) may be disabled for
 * security reasons if this cipher is chosen.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253#section-6.3">RFC 4253 - The
 * Secure Shell (SSH) Transport Layer Protocol: Encryption</a></p>
 *
 * @see org.vngx.jsch.cipher.Cipher
 *
 * @author Michael Laudati
 */
public final class CipherNone implements Cipher {

	/** Constant IV size for empty cipher. */
	private static final int IV_SIZE = 8;
	/** Constant block size for empty cipher. */
	private static final int BLOCK_SIZE = 16;


	@Override
	public int getIVSize() {
		return IV_SIZE;
	}

	@Override
	public int getBlockSize() {
		return BLOCK_SIZE;
	}
	
	@Override
	public boolean isCBC() {
		return false;
	}

	@Override
	public void init(int mode, byte[] key, byte[] iv) {
		// Do nothing
	}

	@Override
	public void update(byte[] source, int srcOffset, int length, byte[] dest, int destOffset) {
		// Do nothing
	}

}
