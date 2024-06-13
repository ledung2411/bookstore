package com.bookstore.controller;

import com.bookstore.entity.User;
import com.bookstore.services.UserServices;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.List;

@Controller
public class UserController {

    @Autowired
    private UserServices userService;

    @GetMapping("/login")
    public String login() {
        return "user/login";
    }

    @GetMapping("/register")
    public String register(Model model) {
        model.addAttribute("user", new User());
        return "user/register";
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute("user") User user,
                           BindingResult bindingResult, Model model) {
        if (bindingResult.hasErrors()) {
            List<FieldError> errors = bindingResult.getFieldErrors();
            for (FieldError error : errors) {
                model.addAttribute(error.getField() + "_error", error.getDefaultMessage());
            }
            return "user/register";
        }
        user.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
        userService.save(user);
        return "redirect:/login";
    }
    @GetMapping("/forgot-password")
    public String showForgotPasswordForm() {
        return "fg_rs_Password/forgot-password";
    }

    @PostMapping("/forgot-password")
    public String processForgotPassword(@RequestParam("email") String email, Model model) {
        boolean result = userService.processForgotPassword(email);
        if (result) {
            model.addAttribute("message", "Đã gửi email đặt lại mật khẩu!");
        } else {
            model.addAttribute("error", "Email không tồn tại trong hệ thống!");
        }
        return "fg_rs_Password/forgot-password";
    }
    @GetMapping("/reset-password")
    public String showResetPasswordForm(@RequestParam("token") String token, Model model) {
        if (!userService.isValidToken(token)) {
            model.addAttribute("error", "Token không hợp lệ hoặc đã hết hạn.");
            return "reset-password";
        }
        model.addAttribute("token", token);
        return "fg_rs_Password/reset-password";
    }

    @PostMapping("/reset-password")
    public String processResetPassword(@RequestParam("token") String token,
                                       @RequestParam("password") String password, Model model) {
        if (userService.updatePassword(token, password)) {
            model.addAttribute("message", "Mật khẩu đã được đặt lại thành công!");
        } else {
            model.addAttribute("error", "Token không hợp lệ hoặc đã hết hạn.");
        }
        return "fg_rs_Password/reset-password";
    }
}
