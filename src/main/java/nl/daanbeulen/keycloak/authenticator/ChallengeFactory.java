package nl.daanbeulen.keycloak.authenticator;

import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.forms.login.LoginFormsProvider;

public class ChallengeFactory {

    private static final Logger logger = Logger.getLogger(ChallengeFactory.class);

    private static final String OTP_PAGE = "http-gateway-otp.ftl";
    private static final String NO_PHONE_NUMBER_PAGE = "http-gateway-otp-authenticator-error.ftl";

    public static Response challenge(AuthenticationFlowContext context) {
        LoginFormsProvider form = context.form();
        return form.createForm(OTP_PAGE);
    }

    public static Response challengeWithError(AuthenticationFlowContext context, Exception e) {
        logger.error("Error thrown", e);
        LoginFormsProvider form = context.form();
        form.setAttribute("error", "http.gateway.otp.authenticator." + e.getClass().getName());
        return form.createForm(NO_PHONE_NUMBER_PAGE);
    }
}
