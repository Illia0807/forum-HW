package telran.java47.security.filter;

import java.io.IOException;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java47.accounting.dao.UserAccountRepository;
import telran.java47.accounting.model.UserAccount;
@Component
@Order(30)
@RequiredArgsConstructor
public class UpdateUserFilter implements Filter {
	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		// System.out.println(request.getUserPrincipal().getName());
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			if (isUser(request)) {
				chain.doFilter(request, response);
			} else {
				response.sendError(403, "access denied");
			}
		}
		chain.doFilter(request, response);

	}

	private boolean isUser(HttpServletRequest request) {
		String userName = request.getUserPrincipal().getName();

		UserAccount userAccount = userAccountRepository.findById(userName).orElse(null);
		if (userAccount != null) {
			
			return  userAccount.getLogin().equals(userName);
		}
		return false;
	}

	private boolean checkEndPoint(String method, String path) {

		return ("PUT".equalsIgnoreCase(method) && path.matches("/account/user/?"));
	}

}
