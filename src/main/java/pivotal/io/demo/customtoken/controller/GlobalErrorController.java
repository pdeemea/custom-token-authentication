package pivotal.io.demo.customtoken.controller;

import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.web.BasicErrorController;
import org.springframework.boot.autoconfigure.web.ErrorAttributes;
import org.springframework.boot.autoconfigure.web.ErrorProperties;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestAttributes;

/**
 * Our Error Handling strategy is quite simple: We want to leverage Spring Boot out-of-the-box error handling which is provided by the 
 * class <code>BasicErrorController</code>.
 * However we do have 2 requirements. One is that we want to report any 404 NotFound error as 403 Forbidden. And the second requirement is that
 * we want to have an additional request attribute which has the errorCode associated to the exception. This error code  is different from the
 * HTTP error code that the BasicErrorController is already populating it.
 * 
 * We will use this error controller for our Web users. For Restful users we want to handle the errors using a @ControllerAdvise class. 
 * 
 * @author mrosales
 *
 */
public class GlobalErrorController extends BasicErrorController {

	public static String ERROR_CODE_ATTRIBUTE =  "errorCode"; 
	
	public GlobalErrorController(ErrorAttributes errorAttributes, ErrorProperties errorProperties) {
		super(new ErrorCodeAppender(errorAttributes), errorProperties);
	}

	@Override
	protected HttpStatus getStatus(HttpServletRequest request) {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		System.out.println(auth);
		HttpStatus status = super.getStatus(request);
		if (!HttpStatus.NOT_FOUND.equals(status)) {
			return status;	
		}
		status = HttpStatus.FORBIDDEN;
		request.setAttribute("javax.servlet.error.status_code", status.value());
		return status;
	}
	

	static class ErrorCodeAppender implements ErrorAttributes {

		private ErrorAttributes source;
		
		
		public ErrorCodeAppender(ErrorAttributes source) {
			super();
			this.source = source;
		}

		@Override
		public Map<String, Object> getErrorAttributes(RequestAttributes requestAttributes, boolean includeStackTrace) {
			Map<String, Object> attrs  = source.getErrorAttributes(requestAttributes, includeStackTrace);
			attrs.put(ERROR_CODE_ATTRIBUTE, getErrorCode(getError(requestAttributes)));
			return attrs;
		}
		
		private String getErrorCode(Throwable error) {
			if (error == null) {
				return "";
			}
			
			if (error != null) {
				while (error instanceof ServletException && error.getCause() != null) {
					error = ((ServletException) error).getCause();
				}
			}
			
			// To keep things simple on this PoC, the errorCode maps to the Exceptions's simple name. 
			// However, for production/real code we probably want to map the exception to an Error Code/Number. 
			// 
			return error.getClass().getSimpleName(); 
			
		}

		@Override
		public Throwable getError(RequestAttributes requestAttributes) {
			return source.getError(requestAttributes);
		}
		
	}
}
