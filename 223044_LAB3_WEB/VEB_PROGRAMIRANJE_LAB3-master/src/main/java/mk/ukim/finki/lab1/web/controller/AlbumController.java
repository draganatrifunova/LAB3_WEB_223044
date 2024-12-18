package mk.ukim.finki.lab1.web.controller;

import mk.ukim.finki.lab1.model.Album;
import mk.ukim.finki.lab1.model.Song;
import mk.ukim.finki.lab1.repository.AlbumRepository;
import mk.ukim.finki.lab1.service.AlbumService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/albums")
public class AlbumController {

    private final AlbumService albumService;


    public AlbumController(AlbumService albumService) {
        this.albumService = albumService;
    }

    @GetMapping
    public String showAllAlbums(@RequestParam(required = false) String error, Model model){
        List<Album> albumList = albumService.findAll();
        model.addAttribute("albums",albumList);
        model.addAttribute("error", error);
        return "listAlbums.html";
    }

    @PostMapping("/add")
    public String saveSong(@RequestParam(required = false) Long id,
                           @RequestParam String name,
                           @RequestParam String genre,
                           @RequestParam int releaseYear) {

        if (id != null) {
            albumService.editAlbum(id,name, genre, releaseYear);
        } else {
            albumService.addAlbum(name, genre, releaseYear);
        }

        return "redirect:/albums";
    }

    @GetMapping("/edit-form/{id}")
    public String editAlbumPage(@PathVariable Long id, Model model) {
        Album album = albumService.findById(id);
        if(album==null){
            return "redirect:/albums?error=NoAlbumByThatIdFound";
        }
        model.addAttribute("album", album);
        return "add-album";
    }

    @GetMapping("/edit-form")
    public String addSongPage() {
        return "add-album";
    }

    @PostMapping("/delete/{id}")
    public String deleteAlbum(@PathVariable Long id) {
        albumService.deleteAlbum(id);
        return "redirect:/albums";
    }
}
