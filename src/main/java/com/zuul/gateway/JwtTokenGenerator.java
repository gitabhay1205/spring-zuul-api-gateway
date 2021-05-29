package com.zuul.gateway;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Description;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class JwtTokenGenerator {
	
	public String SECRET_KEY = "secretKeyToSign";
	
	@Value("${encrypt.key-store.alias}")
	private String keyStorealias;
	
	@Value("${encrypt.key-store.password}")
	private String keystorepassword;

	@Description("Function to generate token")
	public String generateJwt(String client_id) throws KeyStoreException {
		
		String token = new String();
		
		InputStream input = JwtTokenGenerator.class.getResourceAsStream("/private_key/mytest.jks");
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		try {
			
			keystore.load(input, keystorepassword.toCharArray());
			Key key = keystore.getKey(keyStorealias, keystorepassword.toCharArray());
		
		//claims is anything you want to include in your JWT payload
		Claims claims = Jwts.claims();
		claims.put("scopes",GrantAuthoritiesClass.getAuthorities().stream().map(grant_types->grant_types.toString()).collect(Collectors.toList()));
		claims.put("client_id",client_id);
		
		token = Jwts.builder().setClaims(claims).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.RS256, key).compact();
		} catch(Exception e) {
			
			System.out.println(e.toString());
		}
		
		return token;
	}

	public boolean isJwtTokenExpired(String jwt) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		
		boolean isTokenExpired = new Boolean(null);
		try {
			
			Claims claims = Jwts.parser().setSigningKey(PublicKeyDecoder.publickeydecode()).parseClaimsJws(jwt).getBody();
			isTokenExpired = false;
			
		} catch(io.jsonwebtoken.ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException  e) {
			
			//if(e.getClass() == io.jsonwebtoken.ExpiredJwtException.class) {
				isTokenExpired = true;			
			//}
			
		}
		
		return isTokenExpired;
	}
	
	private static class GrantAuthoritiesClass {
		
		private static Collection<String> getAuthorities() {
		return new ArrayList<String>(Arrays.asList("read","write"));
		}	
	}
	
	@Description("Decoding public key for jwt verification")
	protected static class PublicKeyDecoder {
		
		public static PublicKey publickeydecode() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
			
			byte[] publicKeyAsByteArray = publicKeyFileToByteArray();
			
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyAsByteArray);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			RSAPublicKey rsaPublicKey = (RSAPublicKey) kf.generatePublic(publicKeySpec);
			return rsaPublicKey;
		}

		private static byte[] publicKeyFileToByteArray() throws IOException {
			System.out.println("Formatted String: "+ publicKeyAsStringFormatted());
			String publicKeyAsString = publicKeyAsStringFormatted();
			return Base64.getDecoder().decode(publicKeyAsString.getBytes(StandardCharsets.UTF_8));
		}

		private static String publicKeyAsStringFormatted() throws IOException {
			
			String strippedFile = publicKeyFileReadAsString();
			strippedFile = strippedFile.replace("-----BEGIN PUBLIC KEY-----", "");
			strippedFile = strippedFile.replace("-----END PUBLIC KEY-----", "");
			strippedFile = strippedFile.replace("\r\n", "");
			strippedFile = strippedFile.replace("\n", "");
			
			return new String(strippedFile);
		}

		private static String publicKeyFileReadAsString() throws IOException {
			
			InputStream input = JwtTokenGenerator.class.getResourceAsStream("/private_key/publicKey.txt");
			StringBuilder strBuilder = new StringBuilder();
			Reader reader = new InputStreamReader(input, StandardCharsets.UTF_8);
			BufferedReader buffer = new BufferedReader(reader);
			String line;
			while((line=buffer.readLine())!=null) {
				
				strBuilder.append(line);
			}
			return strBuilder.toString();
		}
		
	}

}
