package pivotal.io.demo.customtoken.exception;

@SuppressWarnings("serial")
public class OutOfServiceException extends RuntimeException {

	public OutOfServiceException(String message) {
		super(message);

	}

	public OutOfServiceException(Throwable cause) {
		super(cause);

	}

	
}
