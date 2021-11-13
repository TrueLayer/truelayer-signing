package truelayer.signing;

public class InvalidKeyException extends RuntimeException {

    private InvalidKeyException(String message, Exception e) {
        super(message, e);
    }

    protected static <T> T evaluate(CheckedSupplier<T> f) {
        try {
            return f.get();
        } catch (InvalidKeyException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }
}
