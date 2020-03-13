package test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

import org.apache.commons.codec.binary.Hex;

public class Test {

    static final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSX");
    static final Base64.Decoder decoder = Base64.getDecoder();
    static final Base64.Encoder encoder = Base64.getEncoder();
    static final String username = "dbtest";
    static final String SHA_256 = "SHA-256";

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String nonceStr = "Hello World Max!";
        byte[] nonceByteArray = nonceStr.getBytes();
        // this is used to calculate password
        String nonce = Hex.encodeHexString(nonceByteArray);
        // this is used as the nonce header
        String nonceBase64 = encoder.encodeToString(nonceByteArray);
        System.out.println(nonceBase64);

        ZonedDateTime now = ZonedDateTime.ofInstant(Instant.now(), ZoneOffset.UTC);
        System.out.println(dateTimeFormatter.format(now));

        String passwordStr = nonce + dateTimeFormatter.format(now) + username;
        MessageDigest digest = MessageDigest.getInstance(SHA_256);
        byte[] passwordByteArray = digest.digest(passwordStr.getBytes());
        String passwordBase64 = encoder.encodeToString(passwordStr.getBytes());
        System.out.println(passwordBase64);
    }
}
