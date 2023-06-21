package telran.java47.security.filter;

import java.io.IOException;
import java.security.Principal;

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
import telran.java47.post.dao.PostRepository;
import telran.java47.post.model.Post;
@Component
@Order(60)
@RequiredArgsConstructor
public class ModeratorFilter implements Filter {
	
	final PostRepository postRepository;
	final UserAccountRepository userAccountRepository;
	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String path = request.getServletPath();
		
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			Principal principal = request.getUserPrincipal();
			System.out.println("delete post");
			String[] arr = path.split("/");
			String id = arr[arr.length - 1];
			Post post=postRepository.findById(id).orElse(null);
			UserAccount userAccount = userAccountRepository.findById(request.getUserPrincipal().getName()).get();
			if(!post.getAuthor().equalsIgnoreCase(principal.getName())||!userAccount.getRoles().contains("MODERATOR".toUpperCase())) {
				response.sendError(403);
				return;
			}
			
		}
		chain.doFilter(request, response);

	}



	private boolean checkEndPoint(String method, String path) {

		return  ("DEL".equalsIgnoreCase(method) && path.matches("/forum/post/\\w+"));
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