package dev.saathi.shield.network.url;

/**
 * Thrown when a raw input cannot be parsed or normalised into a valid URL.
 * Contains user-friendly diagnostic message explaining why the input was rejected.
 */
public class UrlParseException extends Exception {

    public enum ErrorCode {
        EMPTY_INPUT("The web address cannot be empty or blank."),
        INPUT_TOO_LONG("The web address exceeds the maximum supported length of 4096 characters."),
        INVALID_SCHEME("Only HTTP and HTTPS web addresses are supported."),
        DANGEROUS_SCHEME("Potentially dangerous script or local scheme detected."),
        MISSING_HOST("The web address does not contain a valid server name or destination."),
        INVALID_PORT("The port number is outside the valid range (1-65535)."),
        MALFORMED_HOST("The destination server name contains illegal characters or invalid formatting."),
        MALFORMED_UNICODE("The web address contains invalid Unicode characters."),
        GENERAL_MALFORMED("Could not parse web address: ");

        private final String defaultMessage;

        ErrorCode(String defaultMessage) {
            this.defaultMessage = defaultMessage;
        }

        public String getDefaultMessage() {
            return defaultMessage;
        }
    }

    private final ErrorCode errorCode;

    public UrlParseException(ErrorCode errorCode) {
        super(errorCode.getDefaultMessage());
        this.errorCode = errorCode;
    }

    public UrlParseException(ErrorCode errorCode, String detail) {
        super(detail != null && !detail.isBlank() ? detail : errorCode.getDefaultMessage());
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
