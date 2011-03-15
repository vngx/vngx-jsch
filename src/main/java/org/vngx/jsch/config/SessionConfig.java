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

package org.vngx.jsch.config;

import java.util.List;
import java.util.Map;
import org.vngx.jsch.Util;
import org.vngx.jsch.cipher.CipherManager;

/**
 * <p>{@code SessionConfig} allows the user to specify configuration properties
 * for an instance of {@code Session}.  Different sessions running in the same
 * JVM can each have their own independent configurations by creating different
 * instances of {@code SessionConfig}.</p>
 *
 * <p>The user only needs to set properties they wish to override which already
 * exist in the global parent configuration singleton instance
 * {@code JSchConfig}.  Any properties which are not overridden in this
 * instance will be retrieved from the default parent global configuration.</p>
 *
 * @see org.vngx.jsch.config.JSchConfig
 *
 * @author Michael Laudati
 */
public class SessionConfig extends JSchConfig {

	/**
	 * Creates a new instance of {@code SessionConfig} which uses the global
	 * {@code JSchConfig} singleton instance as the parent.
	 */
	public SessionConfig() {
		super(null);
	}

	/**
	 * Creates a new instance of {@code SessionConfig} which uses the specified
	 * parent configuration for retrieving properties not defined in this
	 * configuration instance.
	 *
	 * @param parentConfig
	 */
	public SessionConfig(SessionConfig parentConfig) {
		super(parentConfig);
	}

	/**
	 * Creates a new instance of {@code SessionConfig} with the specified
	 * properties to load.
	 *
	 * @param properties to pre-load
	 * @throws InvalidPropertyException if any invalid properties are included
	 */
	public SessionConfig(Map<String,String> properties) {
		super(null);
		if( properties != null ) {
			for( Map.Entry<String,String> entry : properties.entrySet() ) {
				setProperty(entry.getKey(), entry.getValue());
			}
		}
	}

	/**
	 * Returns the checked list of client to server ciphers.  Each cipher in the
	 * list is checked to verify it's available; any unavailable ciphers are
	 * removed from the list.
	 *
	 * @return comma delimited, checked list of ciphers for client to server in
	 *			order by preference
	 */
	public String getCiphersC2S() {
		List<String> ciphers = CipherManager.getManager().supportedCiphers(getList(KEX_CIPHER_C2S));
		if( ciphers.isEmpty() ) {
			throw new IllegalStateException("No supported client-to-server ciphers: " + getString(KEX_CIPHER_C2S));
		}
		return Util.join(ciphers, ",");
	}

	/**
	 * Returns the checked list of server to client ciphers.  Each cipher in the
	 * list is checked to verify it's available; any unavailable ciphers are
	 * removed from the list.
	 *
	 * @return comma delimited, checked list of ciphers for server to client in
	 *			order by preference
	 */
	public String getCiphersS2C() {
		List<String> ciphers = CipherManager.getManager().supportedCiphers(getList(KEX_CIPHER_S2C));
		if( ciphers.isEmpty() ) {
			throw new IllegalStateException("No supported server-to-client ciphers: " + getString(KEX_CIPHER_S2C));
		}
		return Util.join(ciphers, ",");
	}

}
