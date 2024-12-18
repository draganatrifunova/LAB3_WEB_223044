package mk.ukim.finki.lab1.service.impl;

import mk.ukim.finki.lab1.model.Album;
import mk.ukim.finki.lab1.model.AlbumNotFoundException;
import mk.ukim.finki.lab1.repository.AlbumRepository;
import mk.ukim.finki.lab1.service.AlbumService;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;

@Service
public class AlbumServiceImpl implements AlbumService {
    private final AlbumRepository albumRepository;

    public AlbumServiceImpl(AlbumRepository albumRepository) {
        this.albumRepository = albumRepository;
    }

    @Override
    public List<Album> findAll() {
        return albumRepository.findAll();
    }

    @Override
    public Album findById(Long id) {
        return albumRepository.findById(id).orElseThrow(AlbumNotFoundException::new);
    }

    @Override
    public void deleteAlbum(Long id) {
        albumRepository.deleteById(id);
    }

    @Override
    public Album editAlbum(Long id, String name, String genre, int releaseYear) {
        Album album = albumRepository.findById(id).orElseThrow(AlbumNotFoundException::new);
        album.setName(name);
        album.setGenre(genre);
        album.setReleaseYear(Integer.toString(releaseYear));
        return albumRepository.save(album);
    }

    @Override
    public Album addAlbum(String name, String genre, int releaseYear) {
        Album newAlbum = new Album(name,genre,Integer.toString(releaseYear));
        return albumRepository.save(newAlbum);
    }
}
