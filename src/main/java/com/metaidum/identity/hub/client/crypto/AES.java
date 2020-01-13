package com.metaidum.identity.hub.client.crypto;

import java.security.GeneralSecurityException;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class AES {

	public static byte[] encrptyWithCbcPKCS7Padding(byte[] key, byte[] iv, byte[] message) throws GeneralSecurityException {
		AESEngine aesEngine = new AESEngine();
		CBCBlockCipher blockCipher = new CBCBlockCipher(aesEngine);
		PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher);
		KeyParameter keyParam = new KeyParameter(key);
		ParametersWithIV paramKeyIV = new ParametersWithIV(keyParam, iv);
		
		cipher.init(true, paramKeyIV);
		byte[] outputBytes = new byte[cipher.getOutputSize(message.length)];
		int length = cipher.processBytes(message, 0, message.length, outputBytes, 0);
		try {
			length += cipher.doFinal(outputBytes, length);
		} catch (Exception e) {
			throw new GeneralSecurityException(e);
		}

		return Arrays.copyOfRange(outputBytes, 0, length);
	}
	
	public static byte[] decryptWithCbcPKCS7Padding(byte[] key, byte[] iv, byte[] cipherText) throws GeneralSecurityException {
		AESEngine aesEngine = new AESEngine();
		CBCBlockCipher blockCipher = new CBCBlockCipher(aesEngine);
		PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher);
		KeyParameter keyParam = new KeyParameter(key);
		ParametersWithIV paramKeyIV = new ParametersWithIV(keyParam, iv);
		
		cipher.init(false, paramKeyIV);
		byte[] outputBytes = new byte[cipher.getOutputSize(cipherText.length)];
		int length = cipher.processBytes(cipherText, 0, cipherText.length, outputBytes, 0);
		try {
			length += cipher.doFinal(outputBytes, length);
		} catch (Exception e) {
			throw new GeneralSecurityException(e);
		}

		return Arrays.copyOfRange(outputBytes, 0, length);
		
	}
	
	
}
