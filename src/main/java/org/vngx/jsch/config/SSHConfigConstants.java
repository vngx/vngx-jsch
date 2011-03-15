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

/**
 * Interface to define configuration property name constants along with their
 * respective descriptions.  Clients should use these configuration constants
 * when setting property values in {@code JSchConfig} or {@code SessionConfig}.
 *
 * @see org.vngx.jsch.config.JSchConfig
 * @see org.vngx.jsch.config.SessionConfig
 *
 * @author Michael Laudati
 */
public interface SSHConfigConstants {

	/** Constant for empty string. */
	String EMPTY = "";

	/**
	 * <p>Property name to determine whether strict host key checking is enabled
	 * during the initial key exchange.
	 * <ul>
	 *	<li>"no" indicates server host key errors should be ignored</li>
	 *	<li>"yes" indicates the connection should die immediately
	 *	<li>"ask" indicates the user should be prompted whether to continue</li>
	 * </ul>
	 * </p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code String}<br>
	 * <strong>Values:</strong> "yes" | "ask" | "no"
	 * </p>
	 */
	String STRICT_HOST_KEY_CHECKING = "StrictHostKeyChecking";

	/**
	 * <p>Property name to determine if host names should be hashed before
	 * storing host keys in the known hosts repository file.  Hashing the host
	 * name provides extra security against an attack by preventing an intruder
	 * from seeing other available hosts to connect to from the known hosts.</p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code boolean}<br>
	 * <strong>Values:</strong> {@code true} | {@code false}
	 * </p>
	 */
	String HASH_KNOWN_HOSTS = "HashKnownHosts";

//	/**
//	 * Determines if SSH will check for the server's IP address in the
//	 * known_hosts file.
//	 */
//	String CHECK_HOST_IP = "CheckHostIP";

//	/**
//	 * Turn off host key checking for the local machine only. Useful if you
//	 * set up SSH Port Forwards to remote machines, ala ssh -p 9999
//	 * localhost, but you need to live with the consequences. Better to use
//	 * HostKeyAliases as appropriate
//	 */
//	String NO_HOST_AUTH_FOR_LOCAL = "NoHostAuthenticationForLocalhost";

//	/**
//	 * This option allows you to specify an 'alias' that will be used,
//	 * instead of the actual hostname on the command line, when looking for
//	 * a match in the known_hosts file. Particularly useful for commands
//	 * that use ProxyCommands to connect, or are based on multiple ports
//	 * on a machine that forward to different SSH servers behind it, such as
//	 * a firewall.
//	 */
//	String HOST_KEY_ALIAS = "HostKeyAlias";

//	/**
//	 * The algorithm you prefer, RSA or DSA, for protocol 2 host keys. RSA
//	 * is the default, and unless you have a preference you may as well
//	 * stick with it for performance purposes.
//	 */
//	String HOST_KEY_ALGORITHMS = "HostKeyAlgorithms";

	/**
	 * <p>Property name for a list of authentication methods in priority order
	 * to be used during the initial connection when authenticating the user to
	 * the server.</p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code String} | {@code List<String>}<br>
	 * <strong>Values:</strong> comma-delimited name-list of authentication
	 * methods (e.g. "publickey,keyboard-interactive,password")
	 * </p>
	 */
	String PREFFERED_AUTHS = "PreferredAuthentications";

	/**
	 * <p>Property name for compression level (0-9) to use if/when compressing
	 * outbound SSH data.</p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code int}<br>
	 * <strong>Values:</strong> 0-9
	 * </p>
	 */
	String COMPRESSION_LEVEL = "CompressionLevel";

	/**
	 * <p>Property name to specify the default {@link java.security.Provider}
	 * name to use when generating any cryptographic algorithms based on JCA
	 * including {@code Cipher}s, {@code Hash}es, {@code MAC}s, etc.</p>
	 *
	 * <p><a href="http://download.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html">
	 * Java ™ Cryptography Architecture (JCA) Reference Guide</a></p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code String}<br>
	 * <strong>Values:</strong> provider name (e.g. "BC" for BouncyCastle)
	 * </p>
	 */
	String DEFAULT_SECURITY_PROVIDER = "DefaultSecurityProvider";

	/**
	 * <p>Property to specify the client's proposal for key exchange algorithms.
	 * The value should be a comma-delimited name-list of kex algorithms in
	 * order by preference.</p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code String} | {@code List<String>}<br>
	 * <strong>Values:</strong> comma-delimited name-list of key exchange
	 * algorithms (e.g. "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1")
	 * </p>
	 */
	String KEX_ALGORITHMS = "kex.algorithms";

	/**
	 * <p>Property to specify the client's proposal for server host key
	 * algorithms. The value should be a comma-delimited name-list of algorithms
	 * the client is willing to accept in order by preference.</p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code String} | {@code List<String>}<br>
	 * <strong>Values:</strong> comma-delimited name-list of host key algorithms
	 * (e.g. "ssh-rsa,ssh-dss")
	 * </p>
	 */
	String KEX_SERVER_HOST_KEY = "kex.server_host_key";

	/**
	 * <p>Property to specify the client's proposal for ciphers from server to
	 * client.  The value should be a comma-delimited name-list of ciphers in
	 * order by preference.</p>
	 *
	 * <p><strong>Note:</strong> "none" must be explicitly listed if it is to be
	 * acceptable; the list cannot be empty/null.</p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code String} | {@code List<String>}<br>
	 * <strong>Values:</strong> comma-delimited name-list of cipher algorithms
	 * from server to client (e.g. "aes128-ctr,3des-ctr,blowfish-cbc,aes192-cbc")
	 * </p>
	 */
	String KEX_CIPHER_S2C = "kex.cipher.s2c";

	/**
	 * <p>Property to specify the client's proposal for ciphers from client to
	 * server.  The value should be a comma-delimited name-list of ciphers in
	 * order by preference.</p>
	 *
	 * <p><strong>Note:</strong> "none" must be explicitly listed if it is to be
	 * acceptable; the list cannot be empty/null.</p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code String} | {@code List<String>}<br>
	 * <strong>Values:</strong> comma-delimited name-list of cipher algorithms
	 * from client to server (e.g. "aes128-ctr,3des-ctr,blowfish-cbc,aes192-cbc")
	 * </p>
	 */
	String KEX_CIPHER_C2S = "kex.cipher.c2s";

	/**
	 * <p>Property to specify the client's proposal for MAC algorithms from
	 * server to client.  The value should be a comma-delimited name-list of MAC
	 * algorithms in order by preference.</p>
	 *
	 * <p><strong>Note:</strong> "none" must be explicitly listed if it is to be
	 * acceptable; the list cannot be empty/null.</p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code String} | {@code List<String>}<br>
	 * <strong>Values:</strong> comma-delimited name-list of MAC algorithms from
	 * server to client (e.g. "hmac-sha1,hmac-md5,hmac-sha1-96,hmac-md5-96")
	 * </p>
	 */
	String KEX_MAC_S2C = "kex.mac.s2c";

	/**
	 * <p>Property to specify the client's proposal for MAC algorithms from
	 * client to server.  The value should be a comma-delimited name-list of MAC
	 * algorithms in order by preference.</p>
	 *
	 * <p><strong>Note:</strong> "none" must be explicitly listed if it is to be
	 * acceptable; the list cannot be empty/null.</p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code String} | {@code List<String>}<br>
	 * <strong>Values:</strong> comma-delimited name-list of MAC algorithms from
	 * client to server (e.g. "hmac-sha1,hmac-md5,hmac-sha1-96,hmac-md5-96")
	 * </p>
	 */
	String KEX_MAC_C2S = "kex.mac.c2s";

	/**
	 * <p>Property to specify the client's proposal for compression algorithms
	 * from server to client.  The value should be a comma-delimited name-list
	 * of compression algorithms in order by preference.</p>
	 *
	 * <p><strong>Note:</strong> "none" must be explicitly listed if it is to be
	 * acceptable; the list cannot be empty/null.</p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code String} | {@code List<String>}<br>
	 * <strong>Values:</strong> comma-delimited name-list of compression
	 * algorithms from server to client (e.g. "none,zlib")
	 * </p>
	 */
	String KEX_COMPRESSION_S2C = "kex.compression.s2c";

	/**
	 * <p>Property to specify the client's proposal for compression algorithms
	 * from client to server.  The value should be a comma-delimited name-list
	 * of compression algorithms in order by preference.</p>
	 *
	 * <p><strong>Note:</strong> "none" must be explicitly listed if it is to be
	 * acceptable; the list cannot be empty/null.</p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code String} | {@code List<String>}<br>
	 * <strong>Values:</strong> comma-delimited name-list of compression
	 * algorithms from client to server (e.g. "none,zlib")
	 * </p>
	 */
	String KEX_COMPRESSION_C2S = "kex.compression.c2s";

	/**
	 * <p>Property to specify the client's proposal for language tags from
	 * server to client.  The value should be a comma-delimited name-list of
	 * language tags in order by preference.  The client and/or server MAY
	 * ignore this name-list.  If there are no language preferences, this
	 * name-list SHOULD be empty.  Language tags SHOULD NOT be present unless
	 * they are known to be needed by the sending party.</p>
	 *
	 * <p><strong>Note:</strong> This property can be empty ("").</p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code String} | {@code List<String>}<br>
	 * <strong>Values:</strong> comma-delimited name-list of language tags from
	 * server to client (e.g. "" or "en_US,en_UK")
	 * </p>
	 */
	String KEX_LANG_S2C = "kex.lang.s2c";

	/**
	 * <p>Property to specify the client's proposal for language tags from
	 * client to server.  The value should be a comma-delimited name-list of
	 * language tags in order by preference.  The client and/or server MAY
	 * ignore this name-list.  If there are no language preferences, this
	 * name-list SHOULD be empty.  Language tags SHOULD NOT be present unless
	 * they are known to be needed by the sending party.</p>
	 *
	 * <p><strong>Note:</strong> This property can be empty ("").</p>
	 *
	 * <p>
	 * <strong>Name:</strong> {@value}<br>
	 * <strong>Type:</strong> {@code String} | {@code List<String>}<br>
	 * <strong>Values:</strong> comma-delimited name-list of language tags from
	 * client to server (e.g. "" or "en_US,en_UK")
	 * </p>
	 */
	String KEX_LANG_C2S = "kex.lang.c2s";

}
