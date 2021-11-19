package truelayer.signing;

/**
 * Sign/verification error
 */
public class SignatureException extends RuntimeException {

    private SignatureException(String failureMessage) {
        super(failureMessage);
    }

    public SignatureException(String message, Exception e) {
        super(message, e);
    }

    protected static void ensure(boolean condition, String failureMessage) {
        if (!condition)
            throw new SignatureException(failureMessage);
    }

    protected static <T> T evaluate(CheckedSupplier<T> f) {
        try {
            return f.get();
        } catch (SignatureException e) {
            throw e;
        } catch (Exception e) {
            throw new SignatureException(e.getMessage(), e);
        }
    }

}
