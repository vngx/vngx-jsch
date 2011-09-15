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

package org.vngx.jsch;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.hash.Hash;
import org.vngx.jsch.hash.HashManager;

/**
 * Static utility class containing helper methods including Base64 encoding/
 * decoding, String utility methods and more.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public final class Util {

	/** Constant array of Base 64 characters. */
	private static final byte[] B64 = str2byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");
	/** Constant array of hexadecimal characters. */
	private static final char[] HEXDEC_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	/** MD5 hash implementation to use for generating fingerprints. */
	private static Hash $md5Hash;


	/** Private constructor to prevent instantiation of static utility class. */
	private Util() { }

	/**
	 * Decodes a byte array of base 64 encoded data.
	 *
	 * @param buffer containing base 64 encoded data
	 * @param start position in buffer
	 * @param length of data to decode
	 * @return decoded byte data
	 */
	public static byte[] fromBase64(byte[] buffer, int start, int length) {
		byte[] decoded = new byte[length];
		int j = 0;
		for( int i = start, len = start + length; i < len; i += 4 ) {
			decoded[j] = (byte) ((val(buffer[i]) << 2) | ((val(buffer[i + 1]) & 0x30) >>> 4));
			if( buffer[i + 2] == (byte) '=' ) {
				j++;
				break;
			}
			decoded[j + 1] = (byte) (((val(buffer[i + 1]) & 0x0f) << 4) | ((val(buffer[i + 2]) & 0x3c) >>> 2));
			if( buffer[i + 3] == (byte) '=' ) {
				j += 2;
				break;
			}
			decoded[j + 2] = (byte) (((val(buffer[i + 2]) & 0x03) << 6) | (val(buffer[i + 3]) & 0x3f));
			j += 3;
		}
		return Util.copyOf(decoded, j);
	}

	/**
	 * Returns the index of the specified byte value in the B64 array or 0 if
	 * not found or equal to '='.
	 *
	 * @param input value
	 * @return index in B64 array
	 */
	private static byte val(byte input) {
		if( input == '=' ) {
			return 0;
		}
		for( int j = 0; j < B64.length; j++ ) {
			if( input == B64[j] ) {
				return (byte) j;
			}
		}
		return 0;
	}

	/**
	 * Encodes a byte array of data to base 64 encoding.
	 *
	 * @param buffer containing data to encode
	 * @param start position in buffer
	 * @param length of data to encode
	 * @return base 64 encoded data
	 */
	public static byte[] toBase64(byte[] buffer, int start, int length) {
		byte[] encoded = new byte[length * 2];
		int i = 0, j, k;
		int tmp = (length / 3) * 3 + start; // TODO why divide then multiply by 3
		for( j = start; j < tmp; j += 3 ) {
			k = (buffer[j] >>> 2) & 0x3f;
			encoded[i++] = B64[k];
			k = (buffer[j] & 0x03) << 4 | (buffer[j + 1] >>> 4) & 0x0f;
			encoded[i++] = B64[k];
			k = (buffer[j + 1] & 0x0f) << 2 | (buffer[j + 2] >>> 6) & 0x03;
			encoded[i++] = B64[k];
			k = buffer[j + 2] & 0x3f;
			encoded[i++] = B64[k];
		}

		tmp = (start + length) - tmp;
		if( tmp == 1 ) {
			k = (buffer[j] >>> 2) & 0x3f;
			encoded[i++] = B64[k];
			k = ((buffer[j] & 0x03) << 4) & 0x3f;
			encoded[i++] = B64[k];
			encoded[i++] = (byte) '=';
			encoded[i++] = (byte) '=';
		} else if( tmp == 2 ) {
			k = (buffer[j] >>> 2) & 0x3f;
			encoded[i++] = B64[k];
			k = (buffer[j] & 0x03) << 4 | (buffer[j + 1] >>> 4) & 0x0f;
			encoded[i++] = B64[k];
			k = ((buffer[j + 1] & 0x0f) << 2) & 0x3f;
			encoded[i++] = B64[k];
			encoded[i++] = (byte) '=';
		}
		return Util.copyOf(encoded, i);
	}

	/**
	 * Splits the specified source string into pieces using the specified split
	 * value as the delimiter, returning null if source is null.
	 *
	 * @param source
	 * @param split
	 * @return array of delimited values
	 */
	public static String[] split(String source, String split) {
		return source != null ? source.split(split) : null;
	}

	/**
	 * Pattern matching function which returns true if the specified pattern
	 * matches the specified name.
	 *
	 * @param pattern
	 * @param name
	 * @return true if pattern matches name
	 */
	public static boolean glob(byte[] pattern, byte[] name) {
		return glob0(pattern, 0, name, 0);
	}

	/**
	 * Pattern matching function which returns true if the specified pattern
	 * matches the specified name starting from specified pattern index and
	 * name index.
	 *
	 * @param pattern
	 * @param patternIndex
	 * @param name
	 * @param nameIndex
	 * @return true if pattern matches name from given indexes
	 */
	private static boolean glob0(byte[] pattern, int patternIndex, byte[] name, int nameIndex) {
		if( name.length > 0 && name[0] == '.' ) {
			if( pattern.length > 0 && pattern[0] == '.' ) {
				if( pattern.length == 2 && pattern[1] == '*' ) {
					return true;
				}
				return glob(pattern, patternIndex + 1, name, nameIndex + 1);
			}
			return false;
		}
		return glob(pattern, patternIndex, name, nameIndex);
	}

	/**
	 * Pattern matching function which returns true if the specified pattern
	 * matches the specified name starting from specified pattern index and
	 * name index.
	 *
	 * @param pattern
	 * @param patternIndex
	 * @param name
	 * @param nameIndex
	 * @return true if pattern matches name from given indexes
	 */
	private static boolean glob(byte[] pattern, int patternIndex, byte[] name, int nameIndex) {
		int patternlen = pattern.length;
		if( patternlen == 0 ) {
			return false;
		}

		int namelen = name.length;
		int i = patternIndex;
		int j = nameIndex;

		while( i < patternlen && j < namelen ) {
			if( pattern[i] == '\\' ) {
				if( i + 1 == patternlen ) {
					return false;
				}
				i++;
				if( pattern[i] != name[j] ) {
					return false;
				}
				i += skipUTF8Char(pattern[i]);
				j += skipUTF8Char(name[j]);
				continue;
			}

			if( pattern[i] == '*' ) {
				while( i < patternlen ) {
					if( pattern[i] == '*' ) {
						i++;
						continue;
					}
					break;
				}
				if( patternlen == i ) {
					return true;
				}

				byte tmp = pattern[i];
				if( tmp == '?' ) {
					while( j < namelen ) {
						if( glob(pattern, i, name, j) ) {
							return true;
						}
						j += skipUTF8Char(name[j]);
					}
					return false;
				} else if( tmp == '\\' ) {
					if( i + 1 == patternlen ) {
						return false;
					}
					i++;
					tmp = pattern[i];
					while( j < namelen ) {
						if( tmp == name[j] && glob(pattern, i + skipUTF8Char(tmp), name, j + skipUTF8Char(name[j])) ) {
							return true;
						}
						j += skipUTF8Char(name[j]);
					}
					return false;
				}

				while( j < namelen ) {
					if( tmp == name[j] ) {
						if( glob(pattern, i, name, j) ) {
							return true;
						}
					}
					j += skipUTF8Char(name[j]);
				}
				return false;
			}

			if( pattern[i] == '?' ) {
				i++;
				j += skipUTF8Char(name[j]);
				continue;
			}

			if( pattern[i] != name[j] ) {
				return false;
			}

			i += skipUTF8Char(pattern[i]);
			j += skipUTF8Char(name[j]);

			if( !(j < namelen) ) {			// name is end
				if( !(i < patternlen) ) {	// pattern is end
					return true;
				}
				if( pattern[i] == '*' ) {
					break;
				}
			}
			continue;
		}

		if( i == patternlen && j == namelen ) {
			return true;
		}

		if( !(j < namelen) /*name is end*/ && pattern[i] == '*' ) {
			boolean ok = true;
			while( i < patternlen ) {
				if( pattern[i++] != '*' ) {
					ok = false;
					break;
				}
			}
			return ok;
		}
		return false;
	}

	/**
	 * Adds escape characters for '\', '?' and '*' found in the specified path.
	 *
	 * @param path to quote escape characters
	 * @return quoted path
	 */
	public static String quote(String path) {
		byte[] pathBytes = str2byte(path);
		int count = 0;
		for( byte b : pathBytes ) {
			if( b == '\\' || b == '?' || b == '*' ) {
				count++;
			}
		}
		if( count == 0 ) {
			return path;
		}
		byte[] quotedPath = new byte[pathBytes.length + count];
		for( int i = 0, j = 0; i < pathBytes.length; i++ ) {
			byte b = pathBytes[i];
			if( b == '\\' || b == '?' || b == '*' ) {
				quotedPath[j++] = '\\';
			}
			quotedPath[j++] = b;
		}
		return byte2str(quotedPath);
	}

	/**
	 * Removes any escape characters from the specified path.
	 *
	 * @param path
	 * @return unescaped path
	 */
	public static String unquote(String path) {
		byte[] original = str2byte(path);
		byte[] unquoted = unquote(original);
		if( original.length == unquoted.length ) {
			return path;
		}
		return byte2str(unquoted);
	}

	/**
	 * Removes any escape characters from the specified path.
	 *
	 * @param path
	 * @return unescaped path
	 */
	public static byte[] unquote(byte[] path) {
		int pathLength = path.length, i = 0;
		while( i < pathLength ) {
			if( path[i] == '\\' && i + 1 < pathLength ) {
				System.arraycopy(path, i + 1, path, i, path.length - (i + 1));
				pathLength--;
			}
			i++;
		}
		if( pathLength == path.length ) {
			return path;
		}
		return Util.copyOf(path, pathLength);
	}

	/**
	 * Creates a fingerprint hash of the specified data using the supplied hash.
	 *
	 * @param hash
	 * @param data
	 * @return fingerprint of specified data
	 * @throws JSchException if any errors occur
	 */
	public static String getFingerPrint(Hash hash, byte[] data) throws JSchException {
		try {
			hash.update(data, 0, data.length);
			byte[] digest = hash.digest();
			StringBuilder sb = new StringBuilder(digest.length * 2 + digest.length / 2);
			for( int i = 0, curByte; i < digest.length; i++ ) {
				curByte = digest[i] & 0xff;
				sb.append(HEXDEC_CHARS[(curByte >>> 4) & 0xf]);
				sb.append(HEXDEC_CHARS[(curByte) & 0xf]);
				if( i + 1 < digest.length ) {
					sb.append(':');
				}
			}
			return sb.toString();
		} catch(Exception e) {
			throw new JSchException("Failed to generate fingerprint", e);
		}
	}

	/**
	 * Returns the MD5 hash fingerprint of the specified data.
	 *
	 * @param data to create MD5 hash fingerprint of
	 * @return MD5 hash fingerprint
	 * @throws JSchException if any errors occur
	 */
	public synchronized static String getFingerPrint(byte[] data) throws JSchException {
		if( $md5Hash == null ) {
			$md5Hash = HashManager.getManager().createHash(Hash.HASH_MD5);
		}
		return getFingerPrint($md5Hash, data);
	}

	/**
	 * Converts the specified String to a byte array using the specified 
	 * encoding.  If a UnsupportedEncodingException is thrown, then the default
	 * encoding is used.
	 *
	 * @param str
	 * @param encoding
	 * @return bytes of string
	 */
	public static byte[] str2byte(String str, String encoding) {
		if( str == null ) {
			return null;
		}
		try {
			return str.getBytes(encoding);
		} catch(UnsupportedEncodingException e) {
			return str.getBytes();
		}
	}

	/**
	 * Converts the specified string to bytes with default UTF-8 encoding.
	 *
	 * @param str
	 * @return UTF-8 encoded bytes of String
	 */
	public static byte[] str2byte(String str) {
		return str2byte(str, "UTF-8");
	}

	/**
	 * Converts the specified range of bytes in the src array to a String using
	 * the specified character encoding.  If an UnsupportedEncodingException is
	 * thrown, uses the default encoding.
	 *
	 * @param src
	 * @param offset
	 * @param length
	 * @param encoding
	 * @return String value
	 */
	public static String byte2str(byte[] src, int offset, int length, String encoding) {
		try {
			return new String(src, offset, length, encoding);
		} catch(UnsupportedEncodingException e) {
			return new String(src, offset, length);
		}
	}

	/**
	 * Converts the specified range of bytes in the src array to a String using
	 * the default UTF-8 character encoding.
	 *
	 * @param src
	 * @param offset
	 * @param length
	 * @return String value
	 */
	public static String byte2str(byte[] src, int offset, int length) {
		return byte2str(src, offset, length, "UTF-8");
	}

	/**
	 * Converts the specified bytes to a String using the specified encoding. If
	 * an UnsupportedEncodingException is thrown, uses the default encoding.
	 *
	 * @param str
	 * @param encoding
	 * @return string from bytes using encoding
	 */
	public static String byte2str(byte[] str, String encoding) {
		return byte2str(str, 0, str.length, encoding);
	}

	/**
	 * Converts the specified bytes to String using default UTF-8 encoding.
	 *
	 * @param str
	 * @return string converted from bytes
	 */
	public static String byte2str(byte[] str) {
		return byte2str(str, 0, str.length, "UTF-8");
	}

	/**
	 * Zeros out the specified byte array.
	 *
	 * @param bytes array to zero out
	 */
	public static void bzero(byte[] bytes) {
		if( bytes != null ) {
			Arrays.fill(bytes, (byte) 0);
		}
	}

	/**
	 * Returns the amount of bytes to skip to next character.
	 *
	 * @param b
	 * @return
	 */
	private static int skipUTF8Char(byte b) {
		if( (byte) (b & 0x80) == 0 ) {
			return 1;
		} else if( (byte) (b & 0xe0) == (byte) 0xc0 ) {
			return 2;
		} else if( (byte) (b & 0xf0) == (byte) 0xe0 ) {
			return 3;
		}
		return 1;
	}

	/**
	 * Joins the String values contained in values using the specified glue
	 * between each join.
	 *
	 * @param values to join
	 * @param glue
	 * @return concatenated String
	 */
	public static String join(Collection<String> values, String glue) {
		if( values == null || values.isEmpty() ) {
			return values != null ? "" : null;
		} else if( glue == null ) {
			glue = "";
		}
		StringBuilder buffer = new StringBuilder(10 * values.size());
		Iterator<String> iter = values.iterator();
		for( int i = 0, size = values.size() - 1; i < size; i++ ) {
			buffer.append(iter.next()).append(glue);
		}
		buffer.append(iter.next());
		return buffer.toString();
	}

	/**
	 * Returns a new array which contains the contents of first followed by
	 * the contents of second.
	 *
	 * @param first array to join
	 * @param second array to join
	 * @return new array containing first and second
	 */
	public static byte[] join(byte[] first, byte[] second) {
		byte[] combined = Util.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, combined, first.length, second.length);
		return combined;
	}

	/**
	 * <p>Sanitizes the specified {@code source} by replacing any control
	 * characters.  When displaying text to a user, such as error or debug
	 * messages, the client software SHOULD replace any control characters
	 * (except tab, carriage return, and newline) with safe sequences to avoid
	 * attacks by sending terminal control characters.</p>
	 *
	 * <p>Replaces any characters outside the ASCII 'safe' range [32-126]
	 * excluding '\n', '\r' and '\t' with the Unicode replacement character
	 * '\uFFFD'.</p>
	 *
	 * <p><a href="http://tools.ietf.org/html/rfc4251#section-9.2">RFC 4251 -
	 * The Secure Shell (SSH) Protocol Architecture: Control Character Filtering
	 * </a></p>
	 *
	 * @param source string to sanitize
	 * @return sanitized string with replaced control characters
	 */
	public static String sanitize(String source) {
		if( source == null || source.length()==0 ) {
			return source;
		}
		StringBuilder buffer = new StringBuilder(source);
		char c;
		for( int i = 0, size = buffer.length(); i < size; i++ ) {
			c = buffer.charAt(i);
			if( (c < 32 || c > 126) && (c != '\n' && c != '\r' && c!= '\t') ) {
				buffer.setCharAt(i, '\uFFFD');
			}
		}
		return buffer.toString();
	}

	/**
	 * This method got added in Java 6
	 * duplicate it here to make it easier to port to android 2.x
	 */
	public static byte[]	copyOf(byte[] src, int newSize) {
		byte[] copy = new byte[newSize];
		if (newSize<=src.length)
			//shorter: just copy the subset
			System.arraycopy(src, 0, copy, 0, newSize);
		else {
			//longer: copy whole source and pad with zeroes
			System.arraycopy(src, 0, copy, 0, src.length);
			Arrays.fill(copy, src.length, newSize, (byte) 0);
		}
		return	copy;
	}
}
