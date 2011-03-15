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

package org.vngx.jsch.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import org.vngx.jsch.Buffer;
import org.vngx.jsch.Util;
import org.vngx.jsch.algorithm.AlgorithmManager;
import org.vngx.jsch.algorithm.Algorithms;
import org.vngx.jsch.algorithm.Random;
import org.vngx.jsch.cipher.Cipher;
import org.vngx.jsch.cipher.CipherManager;
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.hash.Hash;
import org.vngx.jsch.hash.HashManager;

/**
 * Abstract implementation of a key pair.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public abstract class KeyPair {

	/** Constant to indicate SSH vendor is OpenSSH. */
	static final int VENDOR_OPENSSH = 0;
	/** Constant to indicate SSH vendor is FSecure. */
	static final int VENDOR_FSECURE = 1;
	
	/** Constant byte[] representation of new line character. */
	private static final byte[] CR = Util.str2byte("\n");
	/** Constant byte[] representation of space character. */
	private static final byte[] SPACE = Util.str2byte(" ");
	/** Constant array of bytes for headers. */
	private static final byte[][] HEADER = {
		Util.str2byte("Proc-Type: 4,ENCRYPTED"),
		Util.str2byte("DEK-Info: DES-EDE3-CBC,")
	};


	public static KeyPair genKeyPair(KeyType type) throws JSchException {
		return genKeyPair(type, 1024);
	}

	public static KeyPair genKeyPair(KeyType type, int keySize) throws JSchException {
		KeyPair keyPair;
		switch( type ) {
			case SSH_DSS: keyPair = new KeyPairDSA(); break;
			case SSH_RSA: keyPair = new KeyPairRSA(); break;
			default: throw new JSchException("Unsupported KeyType: "+type);
		}
		keyPair.generate(keySize);	// Generate keys for the specified size
		return keyPair;				// and return key pair
	}


	/** Instance of 3DES-CBC Cipher for creating keys. */
	private final Cipher _cipher;
	/** Instance of MD5 HASH used for creating fingerprints. */
	private final Hash _hash;
	/** Instance of Random used for generating keys. */
	private final Random _random;
	
	/** Vendor to generate key pair for. */
	int _vendor = VENDOR_OPENSSH;

	byte[] _passphrase;
	boolean _encrypted = false;
	byte[] _data;
	byte[] _iv;
	byte[] _publicKeyBlob;


	/**
	 * Creates a new instance of <code>KeyPair</code> and generates the cipher,
	 * hash and random instances for creating keys.
	 *
	 * @throws IllegalStateException if hash, random or cipher instances fail
	 */
	public KeyPair() {
		try {
			// Generate HASH, Random and Cipher instances
			_hash = HashManager.getManager().createHash(Hash.HASH_MD5);
			_random = AlgorithmManager.getManager().createAlgorithm(Algorithms.RANDOM);
			_cipher = CipherManager.getManager().createCipher(Cipher.CIPHER_3DES_CBC);
		} catch(Exception e) {
			throw new IllegalStateException("Failed to create KeyPair: "+e, e);
		}
	}


	abstract void generate(int keySize) throws JSchException;

	abstract byte[] getBegin();

	abstract byte[] getEnd();

	abstract int getKeySize();

	abstract byte[] getPrivateKey();

	abstract byte[] getKeyTypeName();

	public abstract KeyType getKeyType();

	abstract boolean parse(byte[] data);

	/**
	 * Writes the private key to the specified output stream.
	 *
	 * @param out to write private key to
	 * @throws IOException if an IO error occurs
	 * @throws Exception if any other errors occur
	 */
	public void writePrivateKey(OutputStream out) throws IOException, Exception {
		byte[] plain = getPrivateKey();
		byte[][] ivArray = new byte[1][];
		byte[] encoded = encrypt(plain, ivArray);
		if( encoded != plain ) {
			Util.bzero(plain);
		}
		byte[] iv = ivArray[0];
		byte[] prv = Util.toBase64(encoded, 0, encoded.length);

		out.write(getBegin());
		out.write(CR);
		if( _passphrase != null ) {
			out.write(HEADER[0]);
			out.write(CR);
			out.write(HEADER[1]);
			for( int i = 0; i < iv.length; i++ ) {
				out.write(DataUtil.b2a((byte) ((iv[i] >>> 4) & 0x0f)));
				out.write(DataUtil.b2a((byte) (iv[i] & 0x0f)));
			}
			out.write(CR);
			out.write(CR);
		}
		int i = 0;
		while( i < prv.length ) {
			if( i + 64 < prv.length ) {
				out.write(prv, i, 64);
				out.write(CR);
				i += 64;
				continue;
			}
			out.write(prv, i, prv.length - i);
			out.write(CR);
			break;
		}
		out.write(getEnd());
		out.write(CR);
	}
	
	public byte[] getPublicKeyBlob() {
		return _publicKeyBlob;
	}

	public void writePublicKey(OutputStream out, String comment) throws IOException {
		byte[] pubblob = getPublicKeyBlob();
		byte[] pub = Util.toBase64(pubblob, 0, pubblob.length);
		out.write(getKeyTypeName());
		out.write(SPACE);
		out.write(pub, 0, pub.length);
		out.write(SPACE);
		out.write(Util.str2byte(comment));
		out.write(CR);
	}

	public void writePublicKey(String name, String comment) throws FileNotFoundException, IOException {
		FileOutputStream fos = null;
		try {
			writePublicKey(fos = new FileOutputStream(name), comment);
		} finally {
			if( fos != null ) {
				try { fos.close(); } catch(Exception e) { /* Ignore error. */ }
			}
		}
	}

	public void writeSECSHPublicKey(OutputStream out, String comment) throws IOException {
		byte[] pubblob = getPublicKeyBlob();
		byte[] pub = Util.toBase64(pubblob, 0, pubblob.length);
		out.write(Util.str2byte("---- BEGIN SSH2 PUBLIC KEY ----"));
		out.write(CR);
		out.write(Util.str2byte("Comment: \"" + comment + "\""));
		out.write(CR);
		int index = 0;
		while( index < pub.length ) {
			int len = 70;
			if( (pub.length - index) < len ) {
				len = pub.length - index;
			}
			out.write(pub, index, len);
			out.write(CR);
			index += len;
		}
		out.write(Util.str2byte("---- END SSH2 PUBLIC KEY ----"));
		out.write(CR);
	}

	public void writeSECSHPublicKey(String name, String comment) throws FileNotFoundException, IOException {
		FileOutputStream fos = null;
		try {
			writeSECSHPublicKey(fos = new FileOutputStream(name), comment);
		} finally {
			if( fos != null ) {
				try { fos.close(); } catch(Exception e) { /* Ignore error. */ }
			}
		}
	}

	public void writePrivateKey(String name) throws FileNotFoundException, IOException, Exception {
		FileOutputStream fos = null;
		try {
			writePrivateKey(fos = new FileOutputStream(name));
		} finally {
			if( fos != null ) {
				try { fos.close(); } catch(Exception e) { /* Ignore error. */ }
			}
		}
	}

	/**
	 * Returns a MD5 hash fingerprint for the public key.
	 *
	 * @return MD5 hash fingerprint of public key
	 * @throws JSchException if any errors occur
	 */
	public String getFingerPrint() throws JSchException {
		byte[] kblob = getPublicKeyBlob();
		if( kblob == null ) {
			return null;
		}
		return getKeySize() + " " + Util.getFingerPrint(_hash, kblob);
	}

	private byte[] encrypt(byte[] plain, byte[][] ivReturn) throws Exception {
		if( _passphrase == null ) {
			return plain;
		}
		byte[] encoded = plain;
		byte[] iv = ivReturn[0] = new byte[_cipher.getIVSize()];
		_random.fill(iv, 0, iv.length);

		{	// PKCS#5Padding
			byte[] foo = new byte[(encoded.length / iv.length + 1) * iv.length];
			System.arraycopy(encoded, 0, foo, 0, encoded.length);
			int padding = iv.length - encoded.length % iv.length;
			for( int i = foo.length - 1; (foo.length - padding) <= i; i-- ) {
				foo[i] = (byte) padding;
			}
			encoded = foo;
		}

		byte[] key = null;
		try {
			_cipher.init(Cipher.ENCRYPT_MODE, key = genKey(_passphrase, iv), iv);
			_cipher.update(encoded, 0, encoded.length, encoded, 0);
		} catch(Exception e) {
			// TODO Error handling?
		} finally {
			Util.bzero(key);	// Always zero out key
		}

		return encoded;
	}

	private byte[] decrypt(byte[] data, byte[] passphrase, byte[] iv) throws Exception {
		byte[] key = null;
		try {
			_cipher.init(Cipher.DECRYPT_MODE, key = genKey(passphrase, iv), iv);
		} finally {
			Util.bzero(key);	// Always zero out key
		}
		byte[] plain = new byte[data.length];
		_cipher.update(data, 0, data.length, plain, 0);
		return plain;
	}

	/*
	hash is MD5
	h(0) <- hash(passphrase, iv);
	h(n) <- hash(h(n-1), passphrase, iv);
	key <- (h(0),...,h(n))[0,..,key.length];
	 */
	synchronized byte[] genKey(byte[] passphrase, byte[] iv) throws Exception {
		byte[] key = new byte[_cipher.getBlockSize()];
		int hsize = _hash.getBlockSize();
		byte[] hn = new byte[key.length / hsize * hsize + (key.length % hsize == 0 ? 0 : hsize)];
		byte[] tmp = null;
		switch( _vendor ) {
			case VENDOR_OPENSSH:
			case VENDOR_FSECURE:
				for( int index = 0; index + hsize <= hn.length; ) {
					if( tmp != null ) {
						_hash.update(tmp, 0, tmp.length);
					}
					_hash.update(passphrase, 0, passphrase.length);
					if( _vendor == VENDOR_OPENSSH ) {
						_hash.update(iv, 0, iv.length);
					}
					tmp = _hash.digest();
					System.arraycopy(tmp, 0, hn, index, tmp.length);
					index += tmp.length;
				}
				System.arraycopy(hn, 0, key, 0, key.length);
				return key;

			default:	// No support for other vendor types
				throw new JSchException("Unsupported vendor type: "+_vendor);
		}
	}

	public void setPassphrase(String passphrase) {
		if( passphrase == null || passphrase.length() == 0 ) {
			setPassphrase((byte[]) null);
		} else {
			setPassphrase(Util.str2byte(passphrase));
		}
	}

	public void setPassphrase(byte[] passphrase) {
		if( passphrase != null && passphrase.length == 0 ) {
			passphrase = null;
		}
		_passphrase = passphrase;
	}

	public boolean isEncrypted() {
		return _encrypted;
	}

	public boolean decrypt(String passphrase) throws Exception {
		if( passphrase == null || passphrase.length() == 0 ) {
			return !_encrypted;
		}
		return decrypt(Util.str2byte(passphrase));
	}

	public boolean decrypt(byte[] passphrase) throws Exception {
		if( !_encrypted ) {
			return true;
		} else if( passphrase == null ) {
			return !_encrypted;
		}
		byte[] bar = new byte[passphrase.length];
		System.arraycopy(passphrase, 0, bar, 0, bar.length);
		passphrase = bar;	// Why make a copy of passphrase?
		try {
			if( parse(decrypt(_data, passphrase, _iv)) ) {
				_encrypted = false;
			}
		} finally {
			Util.bzero(passphrase);
		}
		return !_encrypted;
	}

	public static KeyPair load(String prvkey) throws JSchException {
		String pubkey = prvkey + ".pub";
		if( !new File(pubkey).exists() ) {
			pubkey = null;
		}
		return load(prvkey, pubkey);
	}

	public static KeyPair load(String prvkey, String pubkey) throws JSchException {
		byte[] iv = new byte[8];       // 8
		boolean encrypted = true;
		byte[] buf, data, publickeyblob = null;
		KeyType type = null;
		int vendor = VENDOR_OPENSSH;

		FileChannel fc = null;
		try {
			fc = new FileInputStream(prvkey).getChannel();
			int i = 0, len = (int) fc.size();
			fc.read(ByteBuffer.wrap(buf = new byte[len]));
			fc.close();

			while( i < len ) {
				if( buf[i] == 'B' && buf[i + 1] == 'E' && buf[i + 2] == 'G' && buf[i + 3] == 'I' ) {
					i += 6;
					if( buf[i] == 'D' && buf[i + 1] == 'S' && buf[i + 2] == 'A' ) {
						type = KeyType.SSH_DSS;
					} else if( buf[i] == 'R' && buf[i + 1] == 'S' && buf[i + 2] == 'A' ) {
						type = KeyType.SSH_RSA;
					} else if( buf[i] == 'S' && buf[i + 1] == 'S' && buf[i + 2] == 'H' ) { // FSecure
						type = KeyType.UNKNOWN;
						vendor = VENDOR_FSECURE;
					} else {
						throw new JSchException("invalid privatekey: " + prvkey);
					}
					i += 3;
					continue;
				}
				if( buf[i] == 'C' && buf[i + 1] == 'B' && buf[i + 2] == 'C' && buf[i + 3] == ',' ) {
					i += 4;
					for( int ii = 0; ii < iv.length; ii++ ) {
						iv[ii] = (byte) (((DataUtil.a2b(buf[i++]) << 4) & 0xf0) + (DataUtil.a2b(buf[i++]) & 0xf));
					}
					continue;
				}
				if( buf[i] == 0x0d
						&& i + 1 < buf.length && buf[i + 1] == 0x0a ) {
					i++;
					continue;
				}
				if( buf[i] == 0x0a && i + 1 < buf.length ) {
					if( buf[i + 1] == 0x0a ) {
						i += 2;
						break;
					}
					if( buf[i + 1] == 0x0d
							&& i + 2 < buf.length && buf[i + 2] == 0x0a ) {
						i += 3;
						break;
					}
					boolean inheader = false;
					for( int j = i + 1; j < buf.length; j++ ) {
						if( buf[j] == 0x0a ) {
							break;
						}
						//if(buf[j]==0x0d) break;
						if( buf[j] == ':' ) {
							inheader = true;
							break;
						}
					}
					if( !inheader ) {
						i++;
						encrypted = false;    // no passphrase
						break;
					}
				}
				i++;
			}

			if( type == null ) {
				throw new JSchException("invalid privatekey: " + prvkey);
			}

			int start = i;
			while( i < len ) {
				if( buf[i] == 0x0a ) {
					boolean xd = (buf[i - 1] == 0x0d);
					System.arraycopy(buf, i + 1,
							buf,
							i - (xd ? 1 : 0),
							len - i - 1 - (xd ? 1 : 0));
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
			data = Util.fromBase64(buf, start, i - start);

			if( data.length > 4 && // FSecure
					data[0] == (byte) 0x3f
					&& data[1] == (byte) 0x6f
					&& data[2] == (byte) 0xf9
					&& data[3] == (byte) 0xeb ) {

				Buffer _buf = new Buffer(data);
				_buf.getInt();  // 0x3f6ff9be
				_buf.getInt();
				byte[] _type = _buf.getString();
				byte[] _cipher = _buf.getString();
				String cipher = Util.byte2str(_cipher);
				if( cipher.equals("3des-cbc") ) {
					_buf.getInt();
					byte[] foo = new byte[data.length - _buf.getOffSet()];
					_buf.getBytes(foo);
					data = foo;
					encrypted = true;
					throw new JSchException("unknown privatekey format: " + prvkey);
				} else if( cipher.equals("none") ) {
					_buf.getInt();
					_buf.getInt();
					encrypted = false;
					byte[] foo = new byte[data.length - _buf.getOffSet()];
					_buf.getBytes(foo);
					data = foo;
				}
			}

			if( pubkey != null ) {
				try {
					fc = new FileInputStream(pubkey).getChannel();
					len = (int) fc.size();
					fc.read(ByteBuffer.wrap(buf = new byte[len]));
					fc.close();

					if( buf.length > 4 && // FSecure's public key
							buf[0] == '-' && buf[1] == '-' && buf[2] == '-' && buf[3] == '-' ) {

						boolean valid = true;
						i = 0;
						do {
							i++;
						} while( buf.length > i && buf[i] != 0x0a );
						if( buf.length <= i ) {
							valid = false;
						}

						while( valid ) {
							if( buf[i] == 0x0a ) {
								boolean inheader = false;
								for( int j = i + 1; j < buf.length; j++ ) {
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
						if( buf.length <= i ) {
							valid = false;
						}

						start = i;
						while( valid && i < len ) {
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
						if( valid ) {
							publickeyblob = Util.fromBase64(buf, start, i - start);
							if( type == KeyType.UNKNOWN ) {
								if( publickeyblob[8] == 'd' ) {
									type = KeyType.SSH_DSS;
								} else if( publickeyblob[8] == 'r' ) {
									type = KeyType.SSH_RSA;
								}
							}
						}
					} else {
						if( buf[0] == 's' && buf[1] == 's' && buf[2] == 'h' && buf[3] == '-' ) {
							i = 0;
							while( i < len ) {
								if( buf[i] == ' ' ) {
									break;
								}
								i++;
							}
							i++;
							if( i < len ) {
								start = i;
								while( i < len ) {
									if( buf[i] == ' ' ) {
										break;
									}
									i++;
								}
								publickeyblob = Util.fromBase64(buf, start, i - start);
							}
						}
					}
				} catch(Exception ee) {
					// TODO Error handling???
				}
			}
		} catch(JSchException e) {
			throw e;
		} catch(Exception e) {
			throw new JSchException("Failed to load KeyPair: "+e, e);
		}

		KeyPair keyPair = null;
		switch( type ) {
			case SSH_DSS: keyPair = new KeyPairDSA(); break;
			case SSH_RSA: keyPair = new KeyPairRSA(); break;
			default: throw new JSchException("Unsupported key type: "+type);
		}
		keyPair._encrypted = encrypted;
		keyPair._publicKeyBlob = publickeyblob;
		keyPair._vendor = vendor;

		if( encrypted ) {
			keyPair._iv = iv;
			keyPair._data = data;
		} else if( !keyPair.parse(data) ) {
			throw new JSchException("Invalid private key: " + prvkey);
		}
		return keyPair;
	}

	public void dispose() {
		Util.bzero(_passphrase);
	}

	@Override
	protected void finalize() throws Throwable {
		dispose();
		super.finalize();
	}

}
