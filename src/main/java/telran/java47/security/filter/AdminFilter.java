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
@Order(20)
@RequiredArgsConstructor
public class AdminFilter implements Filter {
	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		// System.out.println(request.getUserPrincipal().getName());
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			if (isAdminOrUser(request)) {
				chain.doFilter(request, response);
			} else {
				response.sendError(403, "access denied");
			}
		}
		chain.doFilter(request, response);

	}

	private boolean isAdminOrUser(HttpServletRequest request) {
		String userName = request.getUserPrincipal().getName();

		UserAccount userAccount = userAccountRepository.findById(userName).orElse(null);
		if (userAccount != null) {
			Set<String> roles = userAccount.getRoles();
			return roles.contains("Administrator") || userAccount.getLogin().equals(userName);
		}
		return false;
	}

	private boolean checkEndPoint(String method, String path) {

		return ("DEL".equalsIgnoreCase(method) && path.matches("/account/user/?"));
	}

}
