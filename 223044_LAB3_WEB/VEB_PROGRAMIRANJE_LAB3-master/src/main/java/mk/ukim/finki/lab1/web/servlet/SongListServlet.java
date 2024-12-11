//package mk.ukim.finki.lab1.web.servlet;
//
//import jakarta.servlet.ServletException;
//import jakarta.servlet.annotation.WebServlet;
//import jakarta.servlet.http.HttpServlet;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import mk.ukim.finki.lab1.model.Song;
//import mk.ukim.finki.lab1.service.SongService;
//import org.thymeleaf.context.WebContext;
//import org.thymeleaf.spring6.SpringTemplateEngine;
//import org.thymeleaf.web.IWebExchange;
//import org.thymeleaf.web.servlet.JakartaServletWebApplication;
//
//import java.io.IOException;
//import java.util.List;
//import java.util.Optional;
//
//@WebServlet(name = "songs", urlPatterns = "/listSongs")
//public class SongListServlet extends HttpServlet {
//    private final SpringTemplateEngine springTemplateEngine;
//    private final SongService songService;
//
//    public SongListServlet(SpringTemplateEngine springTemplateEngine, SongService songService) {
//        this.springTemplateEngine = springTemplateEngine;
//        this.songService = songService;
//    }
//
//    @Override
//    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
//        IWebExchange webExchange = JakartaServletWebApplication
//                .buildApplication(getServletContext())
//                .buildExchange(req, resp);
//
//
//        WebContext context = new WebContext(webExchange);
//
//        String text=req.getParameter("search");
//        List<Song> songs=songService.searchByText(text);
//        context.setVariable("songMatch", songs);
//        context.setVariable("songs", songService.listSongs());
//        this.springTemplateEngine.process("listSongs.html", context, resp.getWriter());
//    }
//
//    @Override
//    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
//            String songId=req.getParameter("songId");
//        resp.sendRedirect(String.format("/artist?Id=%s", songId));
//    }
//
//}
