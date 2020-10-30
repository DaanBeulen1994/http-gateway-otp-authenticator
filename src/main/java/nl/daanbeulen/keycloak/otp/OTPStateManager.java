package nl.daanbeulen.keycloak.otp;

import java.time.LocalDateTime;

import org.keycloak.models.utils.HmacOTP;
import org.keycloak.models.utils.TimeBasedOTP;

import nl.daanbeulen.keycloak.exception.TooManyRetriesException;

public class OTPStateManager {

    private final TimeBasedOTP timeBasedOTP;
    private final String otpSecret;
    private final OTPConfiguration otpConfiguration;

    private String otp;
    private LocalDateTime lastOtpTimestamp;
    private int otpCounter;

    public OTPStateManager(OTPConfiguration otpConfiguration) {
        this.otpConfiguration = otpConfiguration;
        this.timeBasedOTP = new TimeBasedOTP(TimeBasedOTP.HMAC_SHA512, otpConfiguration.getNrOfDigits(), otpConfiguration.getIntervalInSeconds(), TimeBasedOTP.DEFAULT_DELAY_WINDOW);
        this.otpSecret = HmacOTP.generateSecret(otpConfiguration.getSecretLength());
        this.otpCounter = 0;
    }

    public String getOtp() throws TooManyRetriesException {
        if (otp == null || LocalDateTime.now().isAfter(lastOtpTimestamp.plusSeconds(otpConfiguration.getIntervalInSeconds()))) {
            generateNewOtp();
        }
        return otp;
    }
    public boolean validateOtp(String otp) {
        return timeBasedOTP.validateTOTP(otp, otpSecret.getBytes());
    }
    public boolean otpExpired() {
        return LocalDateTime.now().isAfter(lastOtpTimestamp.plusSeconds(otpConfiguration.getIntervalInSeconds()));
    }

    private void generateNewOtp() throws TooManyRetriesException {
        if (otpConfiguration.getMaxNrOfRetries() != null && otpCounter >= otpConfiguration.getMaxNrOfRetries()) {
            throw new TooManyRetriesException();
        }
        this.otp = timeBasedOTP.generateTOTP(otpSecret);
        this.lastOtpTimestamp = LocalDateTime.now();
        this.otpCounter++;
    }
}
