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

package org.vngx.jsch.util;

import org.vngx.jsch.Util;

/**
 * <p><code>Enum</code> constant to represent the different types of host keys.
 * Currently the only supported key types are:
 *
 * <ul>
 *	<li>ssh-dss - DSA</li>
 *	<li>ssh-rsa - RSA</li>
 * </ul>
 *
 * @author Michael Laudati
 */
public enum KeyType {

	/** Constant for SSH-DSS host key type. */
	SSH_DSS("DSA", "ssh-dss"),
	/** Constant for SSH-RSA host key type. */
	SSH_RSA("RSA", "ssh-rsa"),
	/** Constant for unknown/unsupported host key type. */
	UNKNOWN("Unknown", "");
	
	/** Display name for type. */
	public final String DISPLAY_NAME;
	/** SSH constant name for key type. */
	public final String NAME;

	/**
	 * Creates a new <code>KeyType</code> constant with the specified display
	 * name and SSH constant name.
	 *
	 * @param displayName
	 * @param sshValue
	 */
	KeyType(String displayName, String sshValue) {
		DISPLAY_NAME = displayName;
		NAME = sshValue;
	}

	/**
	 * Returns the bytes for the SSH constant name for key type.
	 *
	 * @return bytes for key type name
	 */
	public byte[] getBytes() {
		return Util.str2byte(NAME);
	}

	/**
	 * Returns true if the specified key name String matches this constant.
	 * 
	 * @param name of key type
	 * @return true if string matches key type
	 */
	public boolean equals(String name) {
		return NAME.equals(name);
	}

	/* Return the display name for type. */
	@Override
	public String toString() {
		return NAME;
	}

}
