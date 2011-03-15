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

package org.vngx.jsch.kex;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.vngx.jsch.Buffer;
import org.vngx.jsch.JSch;
import org.vngx.jsch.Util;
import org.vngx.jsch.util.Logger.Level;

/**
 * <p>Value object to store the key exchange proposals guessed from the client's
 * and server's proposals during a key exchange.  The proposal values are
 * encapsulated in the immutable instance created through the factory
 * constructor method {@code createProposal} which takes the client's and
 * server's proposals received during key exchange.</p>
 *
 * <p>Key exchange (kex) begins by each side sending name-lists of supported
 * algorithms.  Each side has a preferred algorithm in each category, and it is
 * assumed that most implementations, at any given time, will use the same
 * preferred algorithm.  Each side MAY guess which algorithm the other side is
 * using, and MAY send an initial key exchange packet according to the
 * algorithm, if appropriate for the preferred method.</p>
 *
 * <p>The guess is considered wrong if:
 * <ul>
 *		<li>the kex algorithm and/or the host key algorithm is guessed wrong
 *			(server and client have different preferred algorithm), or</li>
 *		<li>if any of the other algorithms cannot be agreed upon</li>
 * </ul>
 * </p>
 *
 * <p>Otherwise, the guess is considered to be right, and the optimistically
 * sent packet MUST be handled as the first key exchange packet.</p>
 *
 * <p>However, if the guess was wrong, and a packet was optimistically sent by
 * one or both parties, such packets MUST be ignored (even if the error in the
 * guess would not affect the contents of the initial packet(s)), and the
 * appropriate side MUST send the correct initial packet.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253#section-7">RFC 4253</a> - The
 * Secure Shell (SSH) Transport Layer Protocol - Key Exchange</p>
 *
 * @author Michael Laudati
 */
public final class KexProposal {

	/**
	 * Enum constants for the key exchange proposal types.
	 */
	public enum Proposal {
		/** Constant index for key exchange algorithm. */
		KEX_ALGS,
		/** Constant index for server host key signing algorithm. */
		SERVER_HOST_KEY_ALGS,
		/** Constant index for client encryption algorithm. */
		ENC_ALGS_CTOS,
		/** Constant index for server encryption algorithm. */
		ENC_ALGS_STOC,
		/** Constant index for client MAC algorithm. */
		MAC_ALGS_CTOS,
		/** Constant index for server MAC algorithm. */
		MAC_ALGS_STOC,
		/** Constant index for client compression algorithm. */
		COMP_ALGS_CTOS,
		/** Constant index for server compression algorithm. */
		COMP_ALGS_STOC,
		/** Constant index for client language. */
		LANG_CTOS,
		/** Constant index for server language. */
		LANG_STOC;
	}

	/** Map to store the agreed upon proposals. */
	private final Map<Proposal,String> _agreed = new EnumMap<Proposal,String>(Proposal.class);
	

	/**
	 * Creates a new instance of {@code KexProposal}.  Private constructor
	 * because instances should only be created by the static factory method.
	 */
	private KexProposal() { }

	/**
	 * <p>Guesses the algorithm matches between the client's proposals and the
	 * server's proposals.  If a match cannot be found for any set of required
	 * algorithms, returns null.</p>
	 *
	 * <p>Each proposal buffer consists of a series of Strings as follows:
	 * <pre>
	 *  0 string	client kex_algorithms
	 *	1 string	server_host_key_algorithms
	 *	2 string	encryption_algorithms_client_to_server
	 *	3 string	encryption_algorithms_server_to_client
	 *	4 string	mac_algorithms_client_to_server
	 *	5 string	mac_algorithms_server_to_client
	 *	6 string	compression_algorithms_client_to_server
	 *	7 string	compression_algorithms_server_to_client
	 *	8 string	languages_client_to_server
	 *	9 string	languages_server_to_client
	 * </pre></p>
	 *
	 * <p>Each of the algorithm name-lists MUST be a comma-separated list of
	 * algorithm names (see Algorithm Naming in [SSH-ARCH] and additional
	 * information in [SSH-NUMBERS]).  Each supported (allowed) algorithm MUST
	 * be listed in order of preference, from most to least.</p>
	 *
	 * <p>The first algorithm in each name-list MUST be the preferred (guessed)
	 * algorithm.  Each name-list MUST contain at least one algorithm name.</p>
	 *
	 * @param I_S server key exchange initialization string
	 * @param I_C client key exchange initialization string
	 * @return kex proposals or null if failure to guess
	 * @throws KexException if algorithm negotiation fails
	 */
	static KexProposal createProposal(final byte[] I_S, final byte[] I_C) throws KexException {
		Buffer serverBuffer = new Buffer(I_S);	// Wrap in Buffers to easily
		Buffer clientBuffer = new Buffer(I_C);	// read Strings
		serverBuffer.setOffSet(17);	// Skip over message code and 16 bytes of 
		clientBuffer.setOffSet(17);	// random padding for each buffer

		List<String> serverProposals, clientProposals;
		KexProposal proposal = new KexProposal();
		for( Proposal p : Proposal.values() ) {
			// Parse out server and client proposal lists
			serverProposals = Arrays.asList(Util.split(Util.byte2str(serverBuffer.getString()), ","));
			clientProposals = Arrays.asList(Util.split(Util.byte2str(clientBuffer.getString()), ","));
			if( JSch.getLogger().isEnabled(Level.DEBUG) ) {
				JSch.getLogger().log(Level.DEBUG, "Kex: S proposes "+p+" -> "+serverProposals);
				JSch.getLogger().log(Level.DEBUG, "Kex: C proposes "+p+" -> "+clientProposals);
			}

			// Client preference is used for each proposal; check if server
			// supports each client proposal in preference order until match
			for( String clientProposal : clientProposals ) {
				if( serverProposals.contains(clientProposal) ) {
					proposal.set(p, clientProposal);
					break;	// Finished searching
				}
			}

			// Special case for lang: Both parties MAY ignore this name-list. If
			// there are no language preferences, this name-list SHOULD be empty
			if( (p == Proposal.LANG_CTOS || p == Proposal.LANG_STOC) &&
					clientProposals.size() == 1 && clientProposals.get(0).isEmpty() ) {
				proposal.set(p, "");	// Set empty name-list for lang
			}
			// If failure to find a mutually supported algorithm, must throw an
			// exception and disconnect from server
			else if( proposal.get(p) == null || proposal.get(p).isEmpty() ) {
				throw new KexException("Failed to find mutually supported "+p+": " +
						"client->"+clientProposals+" server->"+serverProposals);
			}
		}
		return proposal;
	}

	/**
	 * Sets the specified proposal to the specified selection.
	 *
	 * @param p proposal to set
	 * @param selection
	 */
	private void set(Proposal p, String selection) {
		_agreed.put(p, selection);
	}

	/**
	 * Returns the selection for the specified proposal {@code p}.
	 *
	 * @param p
	 * @return selection for proposal or null if not defined
	 */
	private String get(Proposal p) {
		return _agreed.get(p);
	}

	/**
	 * Returns the agreed proposal for key exchange algorithm.
	 *
	 * @return key exchange algorithm
	 */
	public String getKexAlg() {
		return _agreed.get(Proposal.KEX_ALGS);
	}

	/**
	 * Returns the agreed proposal for server host key algorithm.
	 *
	 * @return server host key algorithm
	 */
	public String getServerHostKeyAlg() {
		return _agreed.get(Proposal.SERVER_HOST_KEY_ALGS);
	}

	/**
	 * Returns the agreed proposal for cipher algorithm from client-to-server.
	 *
	 * @return cipher algorithm for client-to-server
	 */
	public String getCipherAlgCtoS() {
		return _agreed.get(Proposal.ENC_ALGS_CTOS);
	}

	/**
	 * Returns the agreed proposal for cipher algorithm from server-to-client.
	 *
	 * @return cipher algorithm for server-to-client
	 */
	public String getCipherAlgStoC() {
		return _agreed.get(Proposal.ENC_ALGS_STOC);
	}

	/**
	 * Returns the agreed proposal for MAC algorithm from client-to-server.
	 *
	 * @return MAC algorithm for client-to-server
	 */
	public String getMACAlgCtoS() {
		return _agreed.get(Proposal.MAC_ALGS_CTOS);
	}

	/**
	 * Returns the agreed proposal for MAC algorithm from server-to-client.
	 *
	 * @return MAC algorithm for server-to-client
	 */
	public String getMACAlgStoC() {
		return _agreed.get(Proposal.MAC_ALGS_STOC);
	}

	/**
	 * Returns the agreed proposal for compression algorithm from
	 * client-to-server.
	 *
	 * @return compression algorithm for client-to-server
	 */
	public String getCompressionAlgCtoS() {
		return _agreed.get(Proposal.COMP_ALGS_CTOS);
	}

	/**
	 * Returns the agreed proposal for compression algorithm from
	 * server-to-client.
	 *
	 * @return compression algorithm for server-to-client
	 */
	public String getCompressionAlgStoC() {
		return _agreed.get(Proposal.COMP_ALGS_STOC);
	}

	/**
	 * Returns the agreed proposal for language for client-to-server.
	 *
	 * @return language for client-to-server
	 */
	public String getLangCtoS() {
		return _agreed.get(Proposal.LANG_CTOS);
	}

	/**
	 * Returns the agreed proposal for language for server-to-client.
	 *
	 * @return language for server-to-client
	 */
	public String getLangStoC() {
		return _agreed.get(Proposal.LANG_STOC);
	}

	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder(500);
		buffer.append("Kex proposal: kex alg=").append(getKexAlg());
		buffer.append(" hostkey alg=").append(getServerHostKeyAlg());
		buffer.append(" server->client cipher=").append(getCipherAlgStoC());
		buffer.append(" mac=").append(getMACAlgStoC()).append(" comp=");
		buffer.append(getCompressionAlgStoC()).append(" lang=").append(getLangStoC());
		buffer.append(" client->server cipher=").append(getCipherAlgCtoS());
		buffer.append(" mac=").append(getMACAlgCtoS()).append(" comp=");
		buffer.append(getCompressionAlgCtoS()).append(" lang=").append(getLangCtoS());
		return buffer.toString();
	}

}
