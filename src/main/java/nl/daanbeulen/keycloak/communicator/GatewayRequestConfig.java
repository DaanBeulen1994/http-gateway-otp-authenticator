package nl.daanbeulen.keycloak.communicator;

import static nl.daanbeulen.keycloak.authenticator.HttpGatewayOtpAuthenticatorFactory.HTTP_BODY;
import static nl.daanbeulen.keycloak.authenticator.HttpGatewayOtpAuthenticatorFactory.HTTP_METHOD;
import static nl.daanbeulen.keycloak.authenticator.HttpGatewayOtpAuthenticatorFactory.REQUEST_URL;

import java.util.List;
import java.util.Map;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.UserModel;

import nl.daanbeulen.keycloak.exception.AttributeNotAvailableException;
import nl.daanbeulen.keycloak.exception.NoOtpReplacementFoundException;

public class GatewayRequestConfig {

    public static final String OTP_REPLACEMENT = ":otp!";

    private static final String ATTRIBUTE_PREFIX = "attr:";
    private static final String ATTRIBUTE_SUFFIX = "!";
    private static final Pattern ATTRIBUTE_PATTERN = Pattern.compile(ATTRIBUTE_PREFIX + "(.*)" + ATTRIBUTE_SUFFIX);

    private final String url;
    private final String jsonBody;
    private final String httpMethod;

    public GatewayRequestConfig(AuthenticationFlowContext context) throws NoOtpReplacementFoundException, AttributeNotAvailableException {
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        UserModel user = context.getUser();

        this.url = validateAndReplace(config.get(REQUEST_URL), user);
        this.jsonBody = validateAndReplace(config.get(HTTP_BODY), user);
        this.httpMethod = config.get(HTTP_METHOD);

        validateOtpReplacementPresent();
    }

    public String getUrl() {
        return url;
    }

    public String getJsonBody() {
        return jsonBody;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    private void validateOtpReplacementPresent() throws NoOtpReplacementFoundException {
        if (url.contains(OTP_REPLACEMENT)) {
            return;
        }
        if (jsonBody != null && jsonBody.contains(OTP_REPLACEMENT)) {
            return;
        }
        throw new NoOtpReplacementFoundException();
    }

    private String validateAndReplace(String template, UserModel user) throws AttributeNotAvailableException {
        if (template == null) {
            return null;
        }

        Matcher matcher = ATTRIBUTE_PATTERN.matcher(template);
        if (!matcher.matches()) {
            return template;
        }

        List<String> replacementAttributes = matcher.results()
                                                    .map(MatchResult::group)
                                                    .collect(Collectors.toList());

        for (String attribute : replacementAttributes)  {
            String strippedAttribute = attribute.substring(ATTRIBUTE_PREFIX.length(),
                    attribute.length() - ATTRIBUTE_SUFFIX.length());

            if (user.getFirstAttribute(strippedAttribute) == null) {
                throw new AttributeNotAvailableException();
            }

            template = template.replace(attribute, user.getFirstAttribute(strippedAttribute));
        }

        return template;
    }
}
