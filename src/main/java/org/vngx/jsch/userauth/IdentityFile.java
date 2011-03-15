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

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import org.vngx.jsch.Buffer;
import org.vngx.jsch.Util;
import org.vngx.jsch.algorithm.AlgorithmManager;
import org.vngx.jsch.algorithm.SignatureDSA;
import org.vngx.jsch.algorithm.SignatureRSA;
import org.vngx.jsch.cipher.Cipher;
import org.vngx.jsch.cipher.CipherManager;
import org.vngx.jsch.algorithm.Algorithms;
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.hash.Hash;
import org.vngx.jsch.hash.HashManager;
import org.vngx.jsch.util.DataUtil;
import org.vngx.jsch.util.KeyType;

/**
 * Implementation of <code>Identity</code> for an identity key file.
 *
 * @see org.vngx.jsch.Identity
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public class IdentityFile implements Identity {

	private static final int OPENSSH = 0;
	private static final int FSECURE = 1;
	//private static final int PUTTY = 2;

	/** Name of identity. */
	private final String _identity;
	/** MD5 hash function. */
	private final Hash _hash;
	/** Cipher (3DES-CBC or AES 256) used for encryption. */
	private Cipher _cipher;

	/** Key value. */
	private byte[] _key;
	/** Initialization vector for encryption. */
	private byte[] _iv;
	/** ??? */
	private byte[] _encodedData;
	/** Key type for identity (RSA or DSA). */
	private KeyType _keyType = null;
	/** Vendor type for key file (OpenSSH or FSecure). */
	private int _vendor = OPENSSH;

	private byte[] _publicKeyBlob = null;
	
	private boolean _encrypted = true;

	// DSA
	private byte[] _pDSA;
	private byte[] _qDSA;
	private byte[] _gDSA;
	private byte[] _pubKeyDSA;
	private byte[] _prvKeyDSA;

	// RSA
	private byte[] _nRSA;   // modulus
	private byte[] _eRSA;   // public exponent
	private byte[] _dRSA;   // private exponent


	/**
	 * Factory method to create a new instance of <code>IdentityFile</code> for
	 * the specified private key file and public key file.
	 *
	 * @param prvfile
	 * @param pubfile
	 * @return identity file instance
	 * @throws JSchException
	 */
	public static IdentityFile newInstance(String prvfile, String pubfile) throws JSchException {
		byte[] prvkey, pubkey;
		FileChannel fc = null;

		try {	// Attempt to read in private key file
			fc = new FileInputStream(prvfile).getChannel();
			ByteBuffer bb = ByteBuffer.wrap(prvkey = new byte[(int) fc.size()]);
			fc.read(bb);
		} catch(Exception e) {
			throw new JSchException("Failed to read private key file: "+e, e);
		} finally {
			if( fc != null ) {
				try { fc.close(); } catch(IOException ioe) { /* Ignore error. */ }
				fc = null;
			}
		}

		String _pubfile = pubfile;
		if( pubfile == null ) {
			_pubfile = prvfile + ".pub";
		}

		try {	// Attempt to read in the public key file
			fc = new FileInputStream(_pubfile).getChannel();
			ByteBuffer bb = ByteBuffer.wrap(pubkey = new byte[(int) fc.size()]);
			fc.read(bb);
		} catch(Exception e) {
			if( pubfile != null ) {
				// The pubfile is explicitly given, but not accessible.
				throw new JSchException("Failed to read public key file: "+e, e);
			}
			pubkey = null;	// TODO Temp until figured out...
		} finally {
			if( fc != null ) {
				try { fc.close(); } catch(IOException ioe) { /* Ignore error. */ }
				fc = null;
			}
		}

		// Create new identity instance and return
		return newInstance(prvfile, prvkey, pubkey);
	}

	/**
	 * Factory method to create a new instance of <code>IdentityFile</code> for
	 * the specified name, private key and public key.
	 *
	 * @param name
	 * @param prvkey
	 * @param pubkey
	 * @return identity file
	 * @throws JSchException
	 */
	public static IdentityFile newInstance(String name, byte[] prvkey, byte[] pubkey) throws JSchException {
		try {
			return new IdentityFile(name, prvkey, pubkey);
		} finally {
			Util.bzero(prvkey);
		}
	}

	/**
	 * Private constructor to prevent direct instantiation. Instances should be
	 * created using the factory methods <code>newInstance()</code>.
	 * 
	 * @param name
	 * @param prvkey
	 * @param pubkey
	 * @throws JSchException
	 */
	private IdentityFile(String name, byte[] prvkey, byte[] pubkey) throws JSchException {
		_identity = name;
		try {
			_cipher = CipherManager.getManager().createCipher(Cipher.CIPHER_3DES_CBC);
			_key = new byte[_cipher.getBlockSize()];   // 24
			_iv = new byte[_cipher.getIVSize()];       // 8
			_hash = HashManager.getManager().createHash(Hash.HASH_MD5);

			byte[] buf = prvkey;
			int len = buf.length, i = 0;

			// Loop past any invalid dash data found in some identity files
			while( i < len ) {
				if( buf[i] == '-' && i + 4 < len
						&& buf[i + 1] == '-' && buf[i + 2] == '-'
						&& buf[i + 3] == '-' && buf[i + 4] == '-' ) {
					break;
				}
				i++;
			}

			while( i < len ) {
				if( buf[i] == 'B' && i+3 < len && buf[i + 1] == 'E' && buf[i + 2] == 'G' && buf[i + 3] == 'I' ) {
					i += 6;
					if( buf[i] == 'D' && buf[i + 1] == 'S' && buf[i + 2] == 'A' ) {
						_keyType = KeyType.SSH_DSS;
					} else if( buf[i] == 'R' && buf[i + 1] == 'S' && buf[i + 2] == 'A' ) {
						_keyType = KeyType.SSH_RSA;
					} else if( buf[i] == 'S' && buf[i + 1] == 'S' && buf[i + 2] == 'H' ) { // FSecure
						_keyType = KeyType.UNKNOWN;
						_vendor = FSECURE;
					} else {
						throw new JSchException("invalid privatekey: " + _identity);
					}
					i += 3;
					continue;
				}
				if( buf[i] == 'A' && i+7 < len && buf[i + 1] == 'E' && buf[i + 2] == 'S' && buf[i + 3] == '-'
						&& buf[i + 4] == '2' && buf[i + 5] == '5' && buf[i + 6] == '6' && buf[i + 7] == '-' ) {
					i += 8;
					if( CipherManager.getManager().isSupported(Cipher.CIPHER_AES256_CBC) ) {
						_cipher = CipherManager.getManager().createCipher(Cipher.CIPHER_AES256_CBC);
						_key = new byte[_cipher.getBlockSize()];
						_iv = new byte[_cipher.getIVSize()];
					} else {
						throw new JSchException("privatekey: aes256-cbc is not available " + _identity);
					}
					continue;
				}
				// If AES-192 encryption
				if( buf[i] == 'A' && i + 7 < len && buf[i + 1] == 'E' && buf[i + 2] == 'S' && buf[i + 3] == '-'
						&& buf[i + 4] == '1' && buf[i + 5] == '9' && buf[i + 6] == '2' && buf[i + 7] == '-' ) {
					i += 8;
					if( CipherManager.getManager().isSupported(Cipher.CIPHER_AES192_CBC) ) {
						_cipher = CipherManager.getManager().createCipher(Cipher.CIPHER_AES192_CBC);
						_key = new byte[_cipher.getBlockSize()];
						_iv = new byte[_cipher.getIVSize()];
					} else {
						throw new JSchException("privatekey: aes192-cbc is not available " + _identity);
					}
					continue;
				}
				// If AES-128 encryption
				if( buf[i] == 'A' && i + 7 < len && buf[i + 1] == 'E' && buf[i + 2] == 'S' && buf[i + 3] == '-'
						&& buf[i + 4] == '1' && buf[i + 5] == '2' && buf[i + 6] == '8' && buf[i + 7] == '-' ) {
					i += 8;
					if( CipherManager.getManager().isSupported(Cipher.CIPHER_AES128_CBC) ) {
						_cipher = CipherManager.getManager().createCipher(Cipher.CIPHER_AES128_CBC);
						_key = new byte[_cipher.getBlockSize()];
						_iv = new byte[_cipher.getIVSize()];
					} else {
						throw new JSchException("privatekey: aes128-cbc is not available " + _identity);
					}
					continue;
				}
				if( buf[i] == 'C' && i+3 < len && buf[i + 1] == 'B' && buf[i + 2] == 'C' && buf[i + 3] == ',' ) {
					i += 4;
					for( int ii = 0; ii < _iv.length; ii++ ) {
						_iv[ii] = (byte) (((a2b(buf[i++]) << 4) & 0xf0) + (a2b(buf[i++]) & 0xf));
					}
					continue;
				}
				if( buf[i] == 0x0d && i + 1 < len && buf[i + 1] == 0x0a ) {
					i++;
					continue;
				}
				if( buf[i] == 0x0a && i + 1 < len ) {
					if( buf[i + 1] == 0x0a ) {
						i += 2;
						break;
					}
					if( buf[i + 1] == 0x0d && i + 2 < len && buf[i + 2] == 0x0a ) {
						i += 3;
						break;
					}
					boolean inheader = false;
					for( int j = i + 1; j < len; j++ ) {
						if( buf[j] == 0x0a ) {
							break;
						}
						if( buf[j] == ':' ) {
							inheader = true;
							break;
						}
					}
					if( !inheader ) {
						i++;
						_encrypted = false;    // no passphrase
						break;
					}
				}
				i++;
			}

			if( _keyType == null ) {
				throw new JSchException("invalid privatekey: " + _identity);
			}

			int start = i;
			while( i < len ) {
				if( buf[i] == 0x0a ) {
					boolean xd = (buf[i - 1] == 0x0d);
					System.arraycopy(buf, i + 1, buf, i - (xd ? 1 : 0), len - i - 1 - (xd ? 1 : 0));
					if( xd ) {
						len--;
					}
					len--;
					continue;
				}
				if( buf[i] == '-' ) {
					break;
				}
				i++;
			}
			_encodedData = Util.fromBase64(buf, start, i - start);

			if( _encodedData.length > 4 && // FSecure
					_encodedData[0] == (byte) 0x3f
					&& _encodedData[1] == (byte) 0x6f
					&& _encodedData[2] == (byte) 0xf9
					&& _encodedData[3] == (byte) 0xeb ) {

				Buffer _buf = new Buffer(_encodedData);
				_buf.getInt();  // 0x3f6ff9be
				_buf.getInt();
				byte[] typeName = _buf.getString();
				byte[] cipherName = _buf.getString();
				String cipher = Util.byte2str(cipherName);
				if( cipher.equals("3des-cbc") ) {
					_buf.getInt();
					byte[] foo = new byte[_encodedData.length - _buf.getOffSet()];
					_buf.getBytes(foo);
					_encodedData = foo;
					_encrypted = true;
					throw new JSchException("unknown privatekey format: " + _identity);
				} else if( cipher.equals("none") ) {
					_buf.getInt();
					//_buf.getInt();
					_encrypted = false;
					byte[] foo = new byte[_encodedData.length - _buf.getOffSet()];
					_buf.getBytes(foo);
					_encodedData = foo;
				}
			}

			if( pubkey == null ) {
				return;
			}

			buf = pubkey;
			len = buf.length;

			if( buf.length > 4 && // FSecure's public key
					buf[0] == '-' && buf[1] == '-' && buf[2] == '-' && buf[3] == '-' ) {
				i = 0;
				do {
					i++;
				} while( len > i && buf[i] != 0x0a );
				if( len <= i ) {
					return;
				}
				while( i < len ) {
					if( buf[i] == 0x0a ) {
						boolean inheader = false;
						for( int j = i + 1; j < len; j++ ) {
							if( buf[j] == 0x0a ) {
								break;
							}
							if( buf[j] == ':' ) {
								inheader = true;
								break;
							}
						}
						if( !inheader ) {
							i++;
							break;
						}
					}
					i++;
				}
				if( len <= i ) {
					return;
				}

				start = i;
				while( i < len ) {
					if( buf[i] == 0x0a ) {
						System.arraycopy(buf, i + 1, buf, i, len - i - 1);
						len--;
						continue;
					}
					if( buf[i] == '-' ) {
						break;
					}
					i++;
				}
				_publicKeyBlob = Util.fromBase64(buf, start, i - start);

				if( _keyType == KeyType.UNKNOWN && _publicKeyBlob.length > 8 ) {
					if( _publicKeyBlob[8] == 'd' ) {
						_keyType = KeyType.SSH_DSS;
					} else if( _publicKeyBlob[8] == 'r' ) {
						_keyType = KeyType.SSH_RSA;
					}
				}
			} else {
				if( buf[0] != 's' || buf[1] != 's' || buf[2] != 'h' || buf[3] != '-' ) {
					return;
				}
				i = 0;
				while( i < len ) {
					if( buf[i] == ' ' ) {
						break;
					}
					i++;
				}
				i++;
				if( i >= len ) {
					return;
				}
				start = i;
				while( i < len ) {
					if( buf[i] == ' ' || buf[i] == '\n' ) {
						break;
					}
					i++;
				}
				_publicKeyBlob = Util.fromBase64(buf, start, i - start);
				if( _publicKeyBlob.length < 4 + 7 ) {  // It must start with "ssh-XXX".
					_publicKeyBlob = null;
				}
			}
		} catch(JSchException e) {
			throw e;
		} catch(Exception e) {
			throw new JSchException("Failed to create IdentityFile instance: "+e, e);
		}
	}

	@Override
	public String getAlgorithmName() {
		return _keyType.toString();
	}

	@Override
	public boolean setPassphrase(byte[] passphrase) throws JSchException {
		/*
		hash is MD5
		h(0) <- hash(passphrase, iv);
		h(n) <- hash(h(n-1), passphrase, iv);
		key <- (h(0),...,h(n))[0,..,key.length];
		 */
		try {
			if( _encrypted ) {
				if( passphrase == null ) {
					return false;
				}
				int hsize = _hash.getBlockSize();
				byte[] hn = new byte[_key.length / hsize * hsize + (_key.length % hsize == 0 ? 0 : hsize)];
				byte[] tmp = null;
				if( _vendor == OPENSSH ) {
					for( int index = 0; index + hsize <= hn.length; ) {
						if( tmp != null ) {
							_hash.update(tmp, 0, tmp.length);
						}
						_hash.update(passphrase, 0, passphrase.length);
						_hash.update(_iv, 0, _iv.length > 8 ? 8 : _iv.length);
						tmp = _hash.digest();
						System.arraycopy(tmp, 0, hn, index, tmp.length);
						index += tmp.length;
					}
					System.arraycopy(hn, 0, _key, 0, _key.length);
				} else if( _vendor == FSECURE ) {
					for( int index = 0; index + hsize <= hn.length; ) {
						if( tmp != null ) {
							_hash.update(tmp, 0, tmp.length);
						}
						_hash.update(passphrase, 0, passphrase.length);
						tmp = _hash.digest();
						System.arraycopy(tmp, 0, hn, index, tmp.length);
						index += tmp.length;
					}
					System.arraycopy(hn, 0, _key, 0, _key.length);
				}
			}
			if( decrypt() ) {
				_encrypted = false;
				return true;
			}
			_pDSA = _qDSA = _gDSA = _pubKeyDSA = _prvKeyDSA = null;
			return false;
		} catch(Exception e) {
			throw new JSchException("Failed to set passphrase: "+e, e);
		} finally {
			Util.bzero(passphrase);
		}
	}

	@Override
	public byte[] getPublicKeyBlob() {
		if( _publicKeyBlob != null ) {
			return _publicKeyBlob;
		}

		// Generate public key blob based on key type
		byte[] keyBlob = null;
		switch( _keyType ) {
			case SSH_RSA:
				if( _eRSA == null ) { return null; }
				keyBlob = new byte[KeyType.SSH_RSA.toString().length() + 4
						+ _eRSA.length + 4
						+ _nRSA.length + 4];
				Buffer rsaBuf = new Buffer(keyBlob);
				rsaBuf.putString(KeyType.SSH_RSA.getBytes());
				rsaBuf.putString(_eRSA);
				rsaBuf.putString(_nRSA);
				return keyBlob;

			case SSH_DSS:
				if( _pDSA == null ) { return null; }
				keyBlob = new byte[KeyType.SSH_DSS.toString().length() + 4
						+ _pDSA.length + 4
						+ _qDSA.length + 4
						+ _gDSA.length + 4
						+ _pubKeyDSA.length + 4];
				Buffer dsaBuf = new Buffer(keyBlob);
				dsaBuf.putString(KeyType.SSH_DSS.getBytes());
				dsaBuf.putString(_pDSA);
				dsaBuf.putString(_qDSA);
				dsaBuf.putString(_gDSA);
				dsaBuf.putString(_pubKeyDSA);
				return keyBlob;

			default:
				throw new IllegalStateException("Failed to generate public key blob, invalid key type: "+_keyType);
		}
	}

	@Override
	public byte[] getSignature(byte[] data) {
		switch( _keyType ) {
			case SSH_RSA: {
				try {
					SignatureRSA rsa = AlgorithmManager.getManager().createAlgorithm(Algorithms.SIGNATURE_RSA);
					rsa.setPrvKey(_dRSA, _nRSA);
					rsa.update(data);
					byte[] sig = rsa.sign();
					byte[] buffer = new byte[KeyType.SSH_RSA.toString().length() + 4 + sig.length + 4];
					Buffer buf = new Buffer(buffer);
					buf.putString(KeyType.SSH_RSA.getBytes());
					buf.putString(sig);
					return buffer;
				} catch(Exception e) {
					// TODO Error handling?
				}
				return null;
			}
			case SSH_DSS: {
				try {
					SignatureDSA dsa = AlgorithmManager.getManager().createAlgorithm(Algorithms.SIGNATURE_DSS);
					dsa.setPrvKey(_prvKeyDSA, _pDSA, _qDSA, _gDSA);
					dsa.update(data);
					byte[] sig = dsa.sign();
					byte[] buffer = new byte[KeyType.SSH_DSS.toString().length() + 4 + sig.length + 4];
					Buffer buf = new Buffer(buffer);
					buf.putString(KeyType.SSH_DSS.getBytes());
					buf.putString(sig);
					return buffer;
				} catch(Exception e) {
					// TODO Error handling?
				}
				return null;
			}
			default:
				throw new IllegalStateException("Failed to get signature, invalid key type: "+_keyType);
		}
	}

	@Override
	public boolean decrypt() {
		switch( _keyType ) {
			case SSH_RSA: return decryptRSA();
			case SSH_DSS: return decryptDSS();
			default: throw new IllegalStateException("Failed to decrypt, invalid key type: "+_keyType);
		}
	}

	boolean decryptRSA() {
		try {
			byte[] plain;
			if( _encrypted ) {
				if( _vendor == OPENSSH ) {
					_cipher.init(Cipher.DECRYPT_MODE, _key, _iv);
					plain = new byte[_encodedData.length];
					_cipher.update(_encodedData, 0, _encodedData.length, plain, 0);
				} else if( _vendor == FSECURE ) {
					for( int i = 0; i < _iv.length; i++ ) {
						_iv[i] = 0;
					}
					_cipher.init(Cipher.DECRYPT_MODE, _key, _iv);
					plain = new byte[_encodedData.length];
					_cipher.update(_encodedData, 0, _encodedData.length, plain, 0);
				} else {
					return false;
				}
			} else {
				if( _nRSA != null ) {
					return true;
				}
				plain = _encodedData;
			}

			if( _vendor == FSECURE ) {              // FSecure
				Buffer buf = new Buffer(plain);
				int foo = buf.getInt();
				if( plain.length != foo + 4 ) {
					return false;
				}
				_eRSA = buf.getMPIntBits();
				_dRSA = buf.getMPIntBits();
				_nRSA = buf.getMPIntBits();
				buf.getMPIntBits();	// u_array
				buf.getMPIntBits();	// p_array
				buf.getMPIntBits();	// q_array
				return true;
			}

			int[] index = new int[1];
			int length = 0;
			if( plain[index[0]] != 0x30 ) {
				return false;
			}
			index[0]++; // SEQUENCE
			length = plain[index[0]++] & 0xff;
			if( (length & 0x80) != 0 ) {
				int foo = length & 0x7f;
				length = 0;
				while( foo-- > 0 ) {
					length = (length << 8) + (plain[index[0]++] & 0xff);
				}
			}
			if( plain[index[0]] != 0x02 ) {
				return false;
			}

			DataUtil.readINTEGER(index, plain);
			_nRSA = DataUtil.readINTEGER(index, plain);
			_eRSA = DataUtil.readINTEGER(index, plain);
			_dRSA = DataUtil.readINTEGER(index, plain);
			DataUtil.readINTEGER(index, plain);	// p_array
			DataUtil.readINTEGER(index, plain);	// q_array
			DataUtil.readINTEGER(index, plain);	// dmp1_array
			DataUtil.readINTEGER(index, plain);	// dmq1_array
			DataUtil.readINTEGER(index, plain);	// iqmp_array
		} catch(Exception e) {
			// TODO Error handling?
			return false;
		}
		return true;
	}

	boolean decryptDSS() {
		try {
			byte[] plain;
			if( _encrypted ) {
				if( _vendor == OPENSSH ) {
					_cipher.init(Cipher.DECRYPT_MODE, _key, _iv);
					plain = new byte[_encodedData.length];
					_cipher.update(_encodedData, 0, _encodedData.length, plain, 0);
				} else if( _vendor == FSECURE ) {
					for( int i = 0; i < _iv.length; i++ ) {
						_iv[i] = 0;
					}
					_cipher.init(Cipher.DECRYPT_MODE, _key, _iv);
					plain = new byte[_encodedData.length];
					_cipher.update(_encodedData, 0, _encodedData.length, plain, 0);
				} else {
					return false;
				}
			} else {
				if( _pDSA != null ) {
					return true;
				}
				plain = _encodedData;
			}

			if( _vendor == FSECURE ) {              // FSecure
				Buffer buf = new Buffer(plain);
				int foo = buf.getInt();
				if( plain.length != foo + 4 ) {
					return false;
				}
				_pDSA = buf.getMPIntBits();
				_gDSA = buf.getMPIntBits();
				_qDSA = buf.getMPIntBits();
				_pubKeyDSA = buf.getMPIntBits();
				_prvKeyDSA = buf.getMPIntBits();
				return true;
			}

			int[] index = new int[1];
			int length = 0;
			if( plain[index[0]] != 0x30 ) {
				return false;
			}

			index[0]++; // SEQUENCE
			length = plain[index[0]++] & 0xff;
			if( (length & 0x80) != 0 ) {
				int foo = length & 0x7f;
				length = 0;
				while( foo-- > 0 ) {
					length = (length << 8) + (plain[index[0]++] & 0xff);
				}
			}
			if( plain[index[0]] != 0x02 ) {
				return false;
			}

			DataUtil.readINTEGER(index, plain);
			_pDSA = DataUtil.readINTEGER(index, plain);
			_qDSA = DataUtil.readINTEGER(index, plain);
			_gDSA = DataUtil.readINTEGER(index, plain);
			_pubKeyDSA = DataUtil.readINTEGER(index, plain);
			_prvKeyDSA = DataUtil.readINTEGER(index, plain);
		} catch(Exception e) {
			// TODO Error handling?
			return false;
		}
		return true;
	}

	@Override
	public boolean isEncrypted() {
		return _encrypted;
	}

	@Override
	public String getName() {
		return _identity;
	}

	@Override
	public void clear() {
		Util.bzero(_encodedData);
		Util.bzero(_prvKeyDSA);
		Util.bzero(_dRSA);
		Util.bzero(_key);
		Util.bzero(_iv);
	}

	private static byte a2b(byte c) {
		if( '0' <= c && c <= '9' ) {
			return (byte) (c - '0');
		}
		if( 'a' <= c && c <= 'z' ) {
			return (byte) (c - 'a' + 10);
		}
		return (byte) (c - 'A' + 10);
	}

	@Override
	protected void finalize() throws Throwable {
		clear();
		super.finalize();
	}

	@Override
	public int hashCode() {
		return getName().hashCode();
	}

	@Override
	public boolean equals(Object o) {
		return o == this ||  (o instanceof IdentityFile && getName().equals(((IdentityFile) o).getName()));
	}

}
