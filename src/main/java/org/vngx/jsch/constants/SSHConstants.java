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

package org.vngx.jsch.constants;

/**
 * <p>General constants for the SSH library.</p>
 *
 * @author Michael Laudati
 */
public interface SSHConstants {

	/** 
	 * <p>Default port for SSH connections over TCP/IP.</p>
	 * 
	 * <p>When used over TCP/IP, the server normally listens for connections on
	 * port 22.  This port number has been registered with the IANA, and has 
	 * been officially assigned for SSH.</p>
	 * 
	 * <p><a href="http://tools.ietf.org/html/rfc4253#section-4.1">RFC 4253 -
	 * The Secure Shell (SSH) Transport Layer Protocol: Use over TCP/IP</a></p>
	 */
	int DEFAULT_SSH_PORT = 22;
	/** Constant for localhost address "127.0.0.1". */
	String LOCALHOST = "127.0.0.1";
	/** Default path where known host keys are stored locally. */
	String KNOWN_HOSTS = "known_hosts";

	/**
	 * <p>Constant for standard version SSH 2.0 used during client/server
	 * version exchange.</p>
	 *
	 * <p><a href="http://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 -
	 * The Secure Shell (SSH) Transport Layer Protocol: Protocol Version
	 * Exchange</a></p>
	 */
	String SSH_VERSION_2_0 = "SSH-2.0";
	/**
	 * <p>Constant for standard version SSH 2.0 with backwards compatability
	 * with older 1.x SSH versions used during client/server version
	 * exchange.</p>
	 *
	 * <p>Server implementations MAY support a configurable compatibility flag
	 * that enables compatibility with old versions.  When this flag is on, the
	 * server SHOULD identify its 'protoversion' as "1.99".  Clients using
	 * protocol 2.0 MUST be able to identify this as identical to "2.0".</p>
	 *
	 * <p><a href="http://tools.ietf.org/html/rfc4253#section-5">RFC 4253 -
	 * The Secure Shell (SSH) Transport Layer Protocol: Compatibility With Old
	 * SSH Versions</a></p>
	 */
	String SSH_VERSION_1_99 = "SSH-1.99";

}
