package telran.java47.security.filter;

import java.io.IOException;
import java.security.Principal;
import java.util.EnumSet;

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
import telran.java47.post.dao.PostRepository;
import telran.java47.post.model.Post;
import telran.java47.security.model.User;
@Component
@Order(60)
@RequiredArgsConstructor
public class DeletePostFilter implements Filter {
	
	final PostRepository postRepository;
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String path = request.getServletPath();
		
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			User user = (User) request.getUserPrincipal();
			System.out.println("delete post");
			String[] arr = path.split("/");
			String id = arr[arr.length - 1];
			Post post=postRepository.findById(id).orElse(null);
			
			if(post==null||!(user.getName().equals(post.getAuthor())||user.getRoles().contains(Roles.MODERATOR))) {
				response.sendError(403);
				return;
			}
			
		}
		chain.doFilter(request, response);

	}



	private boolean checkEndPoint(String method, String path) {
		EnumSet<HttpMethod> allowedHttpMethods = EnumSet.of(HttpMethod.PUT, HttpMethod.POST, HttpMethod.DELETE,
				HttpMethod.GET);
		return allowedHttpMethods.contains(HttpMethod.valueOf(method.toUpperCase())) && path.matches("/forum/post/\\w+/?");
	}


	}

	/*
	 * Principal principal = request.getUserPrincipal(); String[] arr =
	 * path.split("/"); String id = arr[arr.length - 1]; Post
	 * post=postRepository.findById(id).orElse(null); UserAccount userAccount =
	 * userAccountRepository.findById(request.getUserPrincipal().getName()).get();
	 * if(!post.getAuthor().equals(principal.getName())||!userAccount.getRoles().
	 * contains("MODERATOR".toUpperCase())) { response.sendError(403); return; }
	 */