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

package org.vngx.jsch.userauth;

import org.vngx.jsch.exception.JSchException;

/**
 * Interface for defining an SSH identity for performing user authentication and
 * agent forwarding.<p>
 *
 * The goal of using Identity/Pubkey authentication is to remove the need for
 * static passwords. Instead of providing a password, which could be captured by
 * a keystroke logger or witnessed as you type it, you have a key pair on your
 * disk that you use to authenticate. Your account on the SSH server has a list
 * of Identities/Pubkeys that it trusts, and if you can prove you have the
 * public and private key then you are granted access without supplying a
 * password.<p>
 *
 * Some of the nice features of this form of authentication are:<p>
 * <ul>
 *		<li>No one can shoulder-surf your password and log in to your accounts;
 *			they'd need both your Identity passphrase and the private key from
 *			your machine.</li>
 *		<li>The server administrator could disable password authentication
 *			entirely, to prevent password guessing attacks.</li>
 *		<li>You can use the ssh-agent and SSH agent forwarding to have your
 *			authentication credentials 'follow' you.</li>
 *		<li>You can place restrictions on Identities/Pubkeys, for example
 *			forbidding port forwards, forcing predetermined commands, regardless
 *			of what the user wanted to run, and more.</li>
 * </ul>
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public interface Identity {

	/**
	 * Sets the passphrase used to retrieve the public key. TODO ???
	 *
	 * @param passphrase
	 * @return
	 * @throws JSchException
	 */
	boolean setPassphrase(byte[] passphrase) throws JSchException;

	/**
	 * Returns the public key blob.
	 *
	 * @return pubic key blob
	 */
	byte[] getPublicKeyBlob();

	/**
	 * Returns a generated signature for the specified data using the key.
	 *
	 * @param data to sign
	 * @return signature for data
	 */
	byte[] getSignature(byte[] data);

	/**
	 * Decrypts the key blob and returns true if successfully decrypted.
	 *
	 * @return true if decrypted
	 */
	boolean decrypt();

	/**
	 * Returns the algorithm name being used for the public key encryption.
	 *
	 * @return algorithm name
	 */
	String getAlgorithmName();

	/**
	 * Returns the name of the identity.
	 *
	 * @return name of identity
	 */
	String getName();

	/**
	 * Returns true if the identity is encrypted.
	 *
	 * @return true if identity is encrypted
	 */
	boolean isEncrypted();

	/**
	 * Clears secure data currently loaded in memory to maintain the highest
	 * security.
	 */
	void clear();
	
}
