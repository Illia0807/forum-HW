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
import telran.java47.security.model.User;
@Component
@Order(40)
@RequiredArgsConstructor
public class AdminRoleFilter implements Filter {
	

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		// System.out.println(request.getUserPrincipal().getName());
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			
			User user=(User) request.getUserPrincipal();
			if(user.getRoles().contains(Roles.ADMINISTARTOR)) {
				response.sendError(407);
				return;
			}
		}
		chain.doFilter(request, response);

	}



	private boolean checkEndPoint(String method, String path) {

		return  path.matches("/account/user/\\w+/role/\\w+/?");
	}

}


//private boolean isAdmin(HttpServletRequest request) {
//String userName = request.getUserPrincipal().getName();
//
//UserAccount userAccount = userAccountRepository.findById(userName).orElse(null);
//if (userAccount != null) {
//	Set<String> roles = userAccount.getRoles();
//	return roles.contains("Administrator") ;
//}
//return false;
//}
