//package mk.ukim.finki.lab1.web.servlet;
//
//import jakarta.servlet.ServletException;
//import jakarta.servlet.annotation.WebServlet;
//import jakarta.servlet.http.HttpServlet;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import mk.ukim.finki.lab1.service.ArtistService;
//import org.thymeleaf.context.WebContext;
//import org.thymeleaf.spring6.SpringTemplateEngine;
//import org.thymeleaf.web.IWebExchange;
//import org.thymeleaf.web.servlet.JakartaServletWebApplication;
//
//import java.io.IOException;
//
//@WebServlet(name = "artistServlet", urlPatterns = "/artist")
//public class ArtistServlet extends HttpServlet {
//    private final SpringTemplateEngine springTemplateEngine;
//    private final ArtistService artistService;
//
//    public ArtistServlet(SpringTemplateEngine springTemplateEngine, ArtistService artistService) {
//        this.springTemplateEngine = springTemplateEngine;
//        this.artistService = artistService;
//    }
//
//    @Override
//    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
//        IWebExchange webExchange = JakartaServletWebApplication
//                .buildApplication(getServletContext())
//                .buildExchange(req, resp);
//
//        WebContext context = new WebContext(webExchange);
//        String songId=req.getParameter("Id");
//        context.setVariable("selected", songId);
//        context.setVariable("artists", artistService.listArtists());
//        this.springTemplateEngine.process("artistsList.html", context, resp.getWriter());
//    }
//
//    @Override
//    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
//        String artist=req.getParameter("artistId");
//        String songId=req.getParameter("songId");
//        resp.sendRedirect(String.format("/songDetails?artId=%s&songId=%s", artist, songId));
//    }
//}
