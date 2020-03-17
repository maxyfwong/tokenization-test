package test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Random;
import java.util.TimeZone;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.bind.DatatypeConverter;

public class Tokenise {

    public static void main(String[] args) throws Exception {
        Tokenise tokenise = new Tokenise();
        String url = new String(
                "https://172.21.112.5/DpmTokenManagerCoreEngine/tokenmanagerRestful/doTokenization");
        String request = new String();
        request = request + "{\"policyName\": \"Email Address\",\"dataList\": {";
        request = request + "\"dataItem\": [{\"identifier\": \"1\", \"inputData\": \"abc@gmail.com\"}]";
        request = request + "}";
        request = request + "}";
        // need to fill in this to test
        String clientName = "";
        String clientPw = "";
        System.out.println(request);
        String response = tokenise.send(clientName, clientPw, url, request);
        System.out.println(response);
    }

    /**
     * Send a JSON request to the DPM Token Manager and return the response * @param
     * endpointUrl
     *
     * @param message
     * @return
     * @throws Exception
     */
    private String send(String clientName, String clientPw, String endpointUrl, String message) throws Exception {
        String nonce = getRandomNonce();
        String timestamp = getCreated();
        // HTTPS connection to the DPM Token Manager and trust any certificate presented
        // by Token Manager
        SSLSocketFactory factory = null;
        if (endpointUrl.startsWith("https")) {
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            TrustManager[] trustAll = new TrustManager[] { new TrustAllCertificates() };
            sslContext.init(null, trustAll, new java.security.SecureRandom());
            factory = sslContext.getSocketFactory();
        }
        // Ignore host mismatches in the server certificate
        HttpsURLConnection conn = (HttpsURLConnection) new URL(endpointUrl).openConnection();
        if (endpointUrl.startsWith("https")) {
            if (factory != null) {
                conn.setSSLSocketFactory(factory);
            }
            conn.setHostnameVerifier(new TrustAllHosts());
        }
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        // Add the required DPM Token Manager header security
        conn.setRequestProperty("username", clientName); // this is the DPM Token Manager client
        conn.setRequestProperty("created", timestamp);
        conn.setRequestProperty("nonce", nonce);
        conn.setRequestProperty("password", digestPassword(nonce, timestamp,
                clientPw));
        // Send the request to the DPM Token Manager
        PrintWriter pw = new PrintWriter(conn.getOutputStream());
        pw.write(message);
        pw.flush();
        pw.close();
        // Read the response from the DPM Token Manager
        InputStream inStream = conn.getInputStream();
        BufferedReader br = new BufferedReader(new InputStreamReader(inStream, "UTF-8"));
        StringBuffer sb = new StringBuffer(1024);
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }
        br.close();
        return sb.toString();
    }

    /**
     * Trust all certificates from any hosts *
     */
    class TrustAllHosts implements HostnameVerifier {
        public boolean verify(String arg0, SSLSession arg1) {
            return true;
        }
    }
    /**
     * Trust all certificates from any hosts
     *
     */
    class TrustAllCertificates implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }

    /**
     * Create a SHA-256 hash for the nonce + timestamp + password (from DPM Token
     * Manager client password)
     *
     * @param nonce
     * @param timestamp
     * @param password
     * @return
     * @throws Exception
     */
    public static String digestPassword(String nonce, String timestamp, String password) throws Exception {
        ByteBuffer buf = ByteBuffer.allocate(1000);
        try {
            buf.put(DatatypeConverter.parseBase64Binary(nonce));
            buf.put(timestamp.getBytes("UTF-8"));
            buf.put(password.getBytes("UTF-8"));
            byte[] toHash = new byte[buf.position()];
            buf.rewind();
            buf.get(toHash);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(toHash);
            String hashBase64String = DatatypeConverter.printBase64Binary(hash);
            return hashBase64String;
        } catch (Exception e) {
            throw new Exception("Failed to calculate hash using algorithm[" + "]", e);
        }
    }

    /**
     * Create a nonce for the request header to the DPM Token Manager * @return
     */
    public static String getRandomNonce() {
        byte[] nonce = new byte[16];
        try {
            Random rand = SecureRandom.getInstance("SHA1PRNG");
            rand.nextBytes(nonce);
            return DatatypeConverter.printBase64Binary(nonce);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    /**
     * Create the timestamp of the current time in the format expected by * the DPM
     * Token Manager
     *
     * @return
     */
    public static String getCreated() {
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        df.setTimeZone(TimeZone.getTimeZone("GMT"));
        return df.format(new java.util.Date());
    }
}
