package nl.daanbeulen.keycloak.communicator;

import static nl.daanbeulen.keycloak.communicator.GatewayRequestConfig.OTP_REPLACEMENT;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;

import org.apache.http.HttpHeaders;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.jboss.logging.Logger;

import nl.daanbeulen.keycloak.exception.GatewayCommunicationException;

public class GatewayCommunicator {

    private static final Logger logger = Logger.getLogger(GatewayCommunicator.class);

    public static void sendOtp(String otp, GatewayRequestConfig gatewayRequestConfig, HttpClient httpClient) throws GatewayCommunicationException {
        switch (gatewayRequestConfig.getHttpMethod()) {
            case "GET":
                sendOtpThroughGet(otp, gatewayRequestConfig, httpClient);
                break;
            case "POST":
                sendOtpThroughPost(otp, gatewayRequestConfig, httpClient);
                break;
            case "PUT":
                break;
        }
    }

    private static void sendOtpThroughGet(String otp, GatewayRequestConfig gatewayRequestConfig, HttpClient httpClient) throws GatewayCommunicationException {
        String uriWithOtp = replaceOtp(gatewayRequestConfig.getUrl(), otp);
        HttpGet httpGet = new HttpGet(URI.create(uriWithOtp));
        try {
            logger.info("sending OTP: " + otp);
            httpClient.execute(httpGet);
        } catch (IOException e) {
            throw new GatewayCommunicationException(e);
        }
    }
    private static void sendOtpThroughPost(String otp, GatewayRequestConfig gatewayRequestConfig, HttpClient httpClient) throws GatewayCommunicationException {
        String uri = gatewayRequestConfig.getUrl();
        String body = gatewayRequestConfig.getJsonBody();
        if (gatewayRequestConfig.getUrl().contains(OTP_REPLACEMENT)) {
            uri = replaceOtp(uri, otp);
        } else {
            body = replaceOtp(body, otp);
        }

        try {
            HttpPost httpPost = new HttpPost(uri);
            httpPost.setEntity(new StringEntity(body));
            httpPost.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
            httpClient.execute(httpPost);
        } catch (IOException e) {
            throw new GatewayCommunicationException(e);
        }
    }
    private static String replaceOtp(String template, String otp) {
        return template.replace(OTP_REPLACEMENT, otp);
    }
}
