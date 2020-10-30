package nl.daanbeulen.keycloak.authenticator;

import javax.ws.rs.core.MultivaluedMap;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.CredentialRepresentation;

import nl.daanbeulen.keycloak.communicator.GatewayCommunicator;
import nl.daanbeulen.keycloak.communicator.GatewayRequestConfig;
import nl.daanbeulen.keycloak.exception.AttributeNotAvailableException;
import nl.daanbeulen.keycloak.exception.GatewayCommunicationException;
import nl.daanbeulen.keycloak.exception.NoOtpReplacementFoundException;
import nl.daanbeulen.keycloak.exception.TooManyRetriesException;
import nl.daanbeulen.keycloak.otp.OTPConfiguration;
import nl.daanbeulen.keycloak.otp.OTPStateManager;

public class HttpGatewayOtpAuthenticator implements Authenticator {

    public static final String OTP_STATE_MANAGER_ATTRIBUTE = "otp-state-manager";
    public static final String GATEWAY_REQUEST_CONFIG_ATTRIBUTE = "gateway-request-config";

    public void authenticate(final AuthenticationFlowContext context) {
        // Initialize GatewayRequestConfig
        GatewayRequestConfig gatewayRequestConfig;
        try {
            gatewayRequestConfig = new GatewayRequestConfig(context);
            context.getSession().setAttribute(GATEWAY_REQUEST_CONFIG_ATTRIBUTE, gatewayRequestConfig);
        } catch (NoOtpReplacementFoundException | AttributeNotAvailableException e) {
            context.challenge(ChallengeFactory.challengeWithError(context, e));
            return;
        }

        // Initialize OTPStateManager
        OTPStateManager otpStateManager = new OTPStateManager(new OTPConfiguration(context.getAuthenticatorConfig()));
        context.getSession().setAttribute(OTP_STATE_MANAGER_ATTRIBUTE, otpStateManager);

        // Generate & send initial SMS
        String otp;
        try {
            otp = otpStateManager.getOtp();
        } catch (TooManyRetriesException e) {
            // Will not occur.
            context.challenge(ChallengeFactory.challengeWithError(context, e));
            return;
        }
        try {
            GatewayCommunicator.sendOtp(otp, gatewayRequestConfig, context.getSession().getProvider(HttpClientProvider.class).getHttpClient());
        } catch (GatewayCommunicationException e) {
            context.challenge(ChallengeFactory.challengeWithError(context, e));
            return;
        }

        context.challenge(ChallengeFactory.challenge(context));
    }

    public void action(final AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formParameters = context.getHttpRequest().getFormParameters();
        String otp = formParameters.getFirst(CredentialRepresentation.TOTP);

        OTPStateManager otpStateManager = context.getSession().getAttribute(OTP_STATE_MANAGER_ATTRIBUTE, OTPStateManager.class);
        if (otpStateManager.validateOtp(otp)) {
            context.success();
            return;
        }

        if (otpStateManager.otpExpired()) {
            try {
                String newOtp = otpStateManager.getOtp();
                GatewayRequestConfig gatewayRequestConfig = context.getSession().getAttribute(GATEWAY_REQUEST_CONFIG_ATTRIBUTE, GatewayRequestConfig.class);
                GatewayCommunicator.sendOtp(newOtp, gatewayRequestConfig, context.getSession().getProvider(HttpClientProvider.class).getHttpClient());
            } catch (TooManyRetriesException | GatewayCommunicationException e) {
                context.challenge(ChallengeFactory.challengeWithError(context, e));
                return;
            }
        }

        context.challenge(ChallengeFactory.challenge(context));
    }

    public boolean requiresUser() {
        return true;
    }

    public boolean configuredFor(final KeycloakSession keycloakSession, final RealmModel realmModel, final UserModel userModel) {
        return true;
    }

    public void setRequiredActions(final KeycloakSession keycloakSession, final RealmModel realmModel, final UserModel userModel) {
    }

    public void close() {
    }
}
