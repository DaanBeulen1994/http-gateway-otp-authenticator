package nl.daanbeulen.keycloak.authenticator;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class HttpGatewayOtpAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "http-gateway-otp-authenticator";

    // OTP Properties
    public static final String NR_OF_DIGITS_PROPERTY = "nrOfDigits";
    public static final String INTERVAL_IN_SECONDS = "intervalInSeconds";
    public static final String SECRET_LENGTH = "secretLength";
    public static final String MAX_NR_OF_RETRIES = "maxNrOfRetries";

    // Request Properties
    public static final String REQUEST_URL = "url";
    public static final String HTTP_METHOD = "httpMethod";
    public static final String HTTP_BODY = "body";

    public String getDisplayType() {
        return "Http Gateway OTP Authenticator Factory";
    }

    public String getReferenceCategory() {
        return "totp";
    }

    public boolean isConfigurable() {
        return true;
    }

    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return AuthenticationExecutionModel.Requirement.values();
    }

    public boolean isUserSetupAllowed() {
        return false;
    }

    public String getHelpText() {
        return "Sends a generated OTP to a configured HTTP Gateway and expects the send OTP to be filled in by the user on the OTP page. The HTTP Gateway is responsible for getting the OTP to the user. Examples of the HTTP gateway are SMS services or Email services";
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        // OTP settings
        ProviderConfigProperty nrOfDigits = new ProviderConfigProperty(NR_OF_DIGITS_PROPERTY, "Number of digits", "The number of digits of the generated OTP code.", ProviderConfigProperty.STRING_TYPE, "6");
        ProviderConfigProperty intervalInSeconds = new ProviderConfigProperty(INTERVAL_IN_SECONDS, "OTP lifetime in seconds", "The lifetime of the generated OTP in seconds", ProviderConfigProperty.STRING_TYPE, "60");
        ProviderConfigProperty secretLength = new ProviderConfigProperty(SECRET_LENGTH, "HMAC secret length", "The length of the secret to be used when generating the OTP. This should at least be 160", ProviderConfigProperty.STRING_TYPE, "160");
        ProviderConfigProperty maxNrOfRetries = new ProviderConfigProperty(MAX_NR_OF_RETRIES, "Max number of retries", "The maximum number of times we can resend an SMS.", ProviderConfigProperty.STRING_TYPE, null);

        // Request settings
        ProviderConfigProperty url = new ProviderConfigProperty(REQUEST_URL, "Request URL", "The URL the request should be send to", ProviderConfigProperty.STRING_TYPE, null);
        ProviderConfigProperty httpMethod = new ProviderConfigProperty(HTTP_METHOD, "HTTP Method", "The HTTP Method to use when sending the request", ProviderConfigProperty.STRING_TYPE, null);
        ProviderConfigProperty body = new ProviderConfigProperty(HTTP_BODY, "Body", "The body to include in the HTTP request. Content type is JSON", ProviderConfigProperty.TEXT_TYPE, null);

        return List.of(nrOfDigits, intervalInSeconds, secretLength, maxNrOfRetries, url, httpMethod, body);
    }

    public Authenticator create(final KeycloakSession keycloakSession) {
        return new HttpGatewayOtpAuthenticator();
    }

    public void init(final Config.Scope scope) {
    }

    public void postInit(final KeycloakSessionFactory keycloakSessionFactory) {
    }

    public void close() {
    }

    public String getId() {
        return PROVIDER_ID;
    }
}
