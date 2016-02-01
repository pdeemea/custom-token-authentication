package pivotal.io.demo.customtoken.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.web.BasicErrorController;
import org.springframework.boot.autoconfigure.web.ErrorAttributes;
import org.springframework.boot.autoconfigure.web.ErrorProperties;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ControllerAdvice;

/**
 * GlobalErrorController for MVC Controller(s). RestController(s) are handled by
 * a different @ControllerAdvise class.
 * 
 * This class delegates error handling to BasicErrorController class.
 * We override getStatus method to transform 404 to 403.  
 * 
 * @author mrosales
 *
 */
public class GlobalErrorController extends BasicErrorController {

	
	public GlobalErrorController(ErrorAttributes errorAttributes, ErrorProperties errorProperties) {
		super(errorAttributes, errorProperties);

	}

	@Override
	protected HttpStatus getStatus(HttpServletRequest request) {
		HttpStatus status = super.getStatus(request);
		if (!HttpStatus.NOT_FOUND.equals(status)) {
			return status;	
		}
		status = HttpStatus.FORBIDDEN;
		request.setAttribute("javax.servlet.error.status_code", status.value());
		return status;
	}
	

}
