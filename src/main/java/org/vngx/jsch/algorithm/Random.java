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

package org.vngx.jsch.algorithm;

/**
 * <p>Interface to define an algorithm which generates pseudo-random data used
 * in cryptographic processes.</p>
 *
 * <p>The SSH protocol binds each session key to the session by including random
 * session specific data in the hash used to produce session keys.  Special care
 * should be taken to ensure that all of the random numbers are of good quality.
 * If the random data here (e.g., Diffie-Hellman (DH) parameters) are pseudo-
 * random, then the pseudo-random number generator should be cryptographically
 * secure (i.e., its next output not easily guessed even when knowing all
 * previous outputs) and, furthermore, proper entropy needs to be added to the
 * pseudo-random number generator.  [RFC4086] offers suggestions for sources of
   random numbers and entropy.  Implementers should note the importance of
 * entropy and the well-meant, anecdotal warning about the difficulty in
 * properly implementing pseudo-random number generating functions.</p>
 *
 * <p>The amount of entropy available to a given client or server may sometimes
 * be less than what is required.  In this case, one must either resort to
 * pseudo-random number generation regardless of insufficient entropy or refuse
 * to run the protocol.  The latter is preferable.</p>
 *
 * <br><a href="http://tools.ietf.org/html/rfc4251#section-9.1">RFC 4251 -
 * The Secure Shell (SSH) Protocol Architecture: Pseudo-Random Number
 * Generation</a>
 * <br><a href="http://tools.ietf.org/html/rfc4086">RFC 4086 - Randomness
 * Requirements for Security</a>
 *
 * <p><strong>Note:</strong> Implementations may not be thread-safe and should
 * be externally synchronized.</p>
 *
 * <p><strong>Note:</strong> Instances should be created using the
 * {@code AlgorithmManager} factory.</p>
 *
 * @see org.vngx.jsch.algorithm.AlgorithmManager
 *
 * @author Michael Laudati
 */
public interface Random extends Algorithm {

	/**
	 * Fills the specified array from the offset through length with randomly
	 * generated data.
	 * 
	 * @param buffer array to fill with random bytes
	 * @param offset position in destination
	 * @param length to fill
	 */
	void fill(byte[] buffer, int offset, int length);

}
