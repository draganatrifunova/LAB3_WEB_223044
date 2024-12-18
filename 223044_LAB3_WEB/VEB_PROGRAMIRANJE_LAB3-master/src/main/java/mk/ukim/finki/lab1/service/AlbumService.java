package mk.ukim.finki.lab1.service;

import mk.ukim.finki.lab1.model.Album;

import java.util.List;

public interface AlbumService {
    public List<Album> findAll();

    Album findById (Long id);

    void deleteAlbum(Long id);

    Album editAlbum(Long id, String name, String genre, int releaseYear);

    Album addAlbum(String name, String genre, int releaseYear);
}
