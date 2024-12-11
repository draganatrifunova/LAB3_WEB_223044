package mk.ukim.finki.lab1.service;

import mk.ukim.finki.lab1.model.Artist;

import java.util.List;
import java.util.Optional;

public interface ArtistService{
    List<Artist> listArtists();
    Artist ArtistfindById(Long id);
}
