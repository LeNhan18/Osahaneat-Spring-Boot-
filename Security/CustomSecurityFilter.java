package com.example.demo.Security;

import com.example.demo.Utils.JwtUtilsHelper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;

@Component //Đánh dấu lớp này bằng 1 Spring Bean để xử lý
public class CustomSecurityFilter extends OncePerRequestFilter { ;

    @Autowired
    JwtUtilsHelper jwtUtilsHelper; //Helper Class xử lý JWT

    //Phương thức chính để xử lý mỗi request
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //Bước 1: Trích xuat token tu header qua request
        String token = getTokenFromReader(request);
        System.out.println("Kiem Tra : "+token);
       //Bước 2: Xác thực token
        if (token != null) {
            //Kiểm tra xem token có phải token mình create không?
            if (jwtUtilsHelper.verifyToken(token)) {
                //Tạo đối tượng chứa thông tin xacs thực
                //Ở đây chưa sử dụng thông tin user neen de trống 2 tham số đầu
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken("", "", new ArrayList<>());
                //Bước 3: Lưu thoong tin xác thực vào Security Context
                SecurityContext securityContext = SecurityContextHolder.getContext();

                securityContext.setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        //chấp nhận cho phép đi vào các link api
        //Cho phép request tieeps tục qua các filter khác
        filterChain.doFilter(request, response);

    }
    private String getTokenFromReader(HttpServletRequest request) {

        String BearerToken = request.getHeader("Authorization");
        String token = null;
        if (StringUtils.hasText(BearerToken) && BearerToken.startsWith("Bearer ")) {
            token= BearerToken.substring(7);//lấy dữ liệu sau 7 kí tự

        }
        return token;

    }
    //Hàm này chỉ sử dụng cho việc debug, nó s�� đưa ra token vào console khi bạn gọi đến API

}

