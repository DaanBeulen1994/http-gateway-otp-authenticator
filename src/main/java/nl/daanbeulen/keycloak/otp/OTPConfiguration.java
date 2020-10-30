package nl.daanbeulen.keycloak.otp;

import static nl.daanbeulen.keycloak.authenticator.HttpGatewayOtpAuthenticatorFactory.INTERVAL_IN_SECONDS;
import static nl.daanbeulen.keycloak.authenticator.HttpGatewayOtpAuthenticatorFactory.MAX_NR_OF_RETRIES;
import static nl.daanbeulen.keycloak.authenticator.HttpGatewayOtpAuthenticatorFactory.NR_OF_DIGITS_PROPERTY;
import static nl.daanbeulen.keycloak.authenticator.HttpGatewayOtpAuthenticatorFactory.SECRET_LENGTH;

import java.util.Map;

import org.keycloak.models.AuthenticatorConfigModel;

public class OTPConfiguration {

    private final int nrOfDigits;
    private final int intervalInSeconds;
    private final int secretLength;
    private final Integer maxNrOfRetries;

    public OTPConfiguration(AuthenticatorConfigModel authenticatorConfig) {
        Map<String, String> config = authenticatorConfig.getConfig();
        nrOfDigits = Integer.parseInt(config.get(NR_OF_DIGITS_PROPERTY));
        intervalInSeconds = Integer.parseInt(config.get(INTERVAL_IN_SECONDS));
        secretLength = Integer.parseInt(config.get(SECRET_LENGTH));
        maxNrOfRetries = config.containsKey(MAX_NR_OF_RETRIES) ? Integer.parseInt(config.get(MAX_NR_OF_RETRIES)) : null;
    }

    public int getNrOfDigits() {
        return nrOfDigits;
    }

    public int getIntervalInSeconds() {
        return intervalInSeconds;
    }

    public int getSecretLength() {
        return secretLength;
    }

    public Integer getMaxNrOfRetries() {
        return maxNrOfRetries;
    }
}
