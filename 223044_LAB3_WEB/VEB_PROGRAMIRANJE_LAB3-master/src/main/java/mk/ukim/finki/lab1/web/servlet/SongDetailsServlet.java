//package mk.ukim.finki.lab1.web.servlet;
//
//import jakarta.servlet.ServletException;
//import jakarta.servlet.annotation.WebServlet;
//import jakarta.servlet.http.HttpServlet;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import mk.ukim.finki.lab1.model.Artist;
//import mk.ukim.finki.lab1.model.Song;
//import mk.ukim.finki.lab1.service.ArtistService;
//import mk.ukim.finki.lab1.service.SongService;
//import org.thymeleaf.context.WebContext;
//import org.thymeleaf.spring6.SpringTemplateEngine;
//import org.thymeleaf.web.IWebExchange;
//import org.thymeleaf.web.servlet.JakartaServletWebApplication;
//
//import java.io.IOException;
//
//@WebServlet(name = "song-details", urlPatterns = "/songDetails")
//public class SongDetailsServlet extends HttpServlet {
//    private final SpringTemplateEngine springTemplateEngine;
//    private final SongService songService;
//    private final ArtistService artistService;
//
//    public SongDetailsServlet(SpringTemplateEngine springTemplateEngine, SongService songService, ArtistService artistService) {
//        this.springTemplateEngine = springTemplateEngine;
//        this.songService = songService;
//        this.artistService=artistService;
//    }
//
//    @Override
//    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
//        IWebExchange webExchange = JakartaServletWebApplication
//                .buildApplication(getServletContext())
//                .buildExchange(req, resp);
//
//        WebContext context = new WebContext(webExchange);
//        String ArtistId=req.getParameter("artId");
//        Artist a=artistService.ArtistfindById(Long.parseLong(ArtistId));
//
//        String SongId=req.getParameter("songId");
//        Song s=songService.findByTrackId(Long.valueOf(SongId));
//        songService.addArtistToSong(a, s);
//        context.setVariable("song", s);
//        context.setVariable("artist", a);
//        this.springTemplateEngine.process("songDetails.html", context, resp.getWriter());
//    }
//
//    @Override
//    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
//        resp.sendRedirect("/listSongs");
//    }
//}
