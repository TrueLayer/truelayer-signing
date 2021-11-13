package truelayer.signing;

/**
 * Key error
 */
public class KeyException extends RuntimeException {

    private KeyException(String message, Exception e) {
        super(message, e);
    }

    protected static <T> T evaluate(CheckedSupplier<T> f) {
        try {
            return f.get();
        } catch (KeyException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyException(e.getMessage(), e);
        }
    }
}
