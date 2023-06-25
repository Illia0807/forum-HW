package telran.java47.security.filter;

import java.io.IOException;
import java.security.Principal;
import java.util.EnumSet;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java47.accounting.dao.UserAccountRepository;
import telran.java47.accounting.model.UserAccount;
@Component
@Order(30)
@RequiredArgsConstructor
public class UpdateByOwnerFilter implements Filter {
	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		// System.out.println(request.getUserPrincipal().getName());
		String path=request.getServletPath();
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			Principal principal = request.getUserPrincipal();
			System.out.println(principal);
			String[] arr = path.split("/");
			String user = arr[arr.length - 1];
			if (!principal.getName().equalsIgnoreCase(user)) {
				response.sendError(403);
				return;
			}
		}
		chain.doFilter(request, response);

	}



	
		

		private boolean checkEndPoint(String method, String path) {
			EnumSet<HttpMethod> allowedHttpMethods = EnumSet.of(HttpMethod.PUT, HttpMethod.POST, HttpMethod.DELETE,
					HttpMethod.GET);
			return allowedHttpMethods.contains(HttpMethod.valueOf(method.toUpperCase())) && path.matches("/account/user/\\w+/?")
					|| allowedHttpMethods.contains(HttpMethod.valueOf(method.toUpperCase()))
							&& path.matches("/forum/post/\\w+/comment/\\w+/?");
		}

}
//||path.matches("/forum/post/\\w+?"
//||path.matches("/forum/post/\\w+/comment/\\w+")=

//private boolean isUser(HttpServletRequest request) {
//String userName = request.getUserPrincipal().getName();
//
//UserAccount userAccount = userAccountRepository.findById(userName).orElse(null);
//if (userAccount != null) {
//	
//	return  userAccount.getLogin().equals(userName);
//}
//return false;
//}
