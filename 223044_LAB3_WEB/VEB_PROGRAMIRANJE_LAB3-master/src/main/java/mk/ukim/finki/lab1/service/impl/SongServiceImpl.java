package mk.ukim.finki.lab1.service.impl;

import mk.ukim.finki.lab1.model.Album;
import mk.ukim.finki.lab1.model.Artist;
import mk.ukim.finki.lab1.model.Song;
import mk.ukim.finki.lab1.repository.AlbumRepository;
import mk.ukim.finki.lab1.repository.ArtistRepository;
import mk.ukim.finki.lab1.repository.SongRepository;
import mk.ukim.finki.lab1.service.ArtistService;
import mk.ukim.finki.lab1.service.SongService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class SongServiceImpl implements SongService {
    private final SongRepository songRepository;
    private final AlbumRepository albumRepository;

    @Autowired
    public SongServiceImpl(SongRepository songRepository, AlbumRepository albumRepository) {
        this.songRepository = songRepository;
        this.albumRepository = albumRepository;
    }

    @Override
    public Song addSong(String title, String genre, int releaseYear, Long albumId) {
        Album album = albumRepository.findById(albumId).orElseThrow(() -> new RuntimeException("Album not found"));
        Song song = new Song(title, genre, releaseYear, album);
        return songRepository.save(song);
    }

    @Override
    public Song editSong(Long id, String title, String genre, int releaseYear, Long albumId) {
        Song song = songRepository.findById(id).orElseThrow(() -> new RuntimeException("Song not found"));
        Album album = albumRepository.findById(albumId).orElseThrow(() -> new RuntimeException("Album not found"));

        song.setTitle(title);
        song.setGenre(genre);
        song.setReleaseYear(releaseYear);
        song.setAlbum(album);

        return songRepository.save(song);
    }

    @Override
    public List<Song> listSongs() {
        return songRepository.findAll();
    }

    @Override
    public Song findByTrackId(Long id) {
        return songRepository.getReferenceById(id);
    }

    @Override
    public List<Song> findByAlbumId(Long albumId) {
        return songRepository.findByAlbumId(albumId);
    }

    @Override
    public void deleteSong(Long id) {
        songRepository.deleteById(id);
    }

    @Override
    public void updateSong(Long id, Song song) {
        Album album = albumRepository.findById(song.getAlbum().getId()).orElseThrow(() -> new RuntimeException("Album not found"));

        song.setTitle(song.getTitle());
        song.setGenre(song.getGenre());
        song.setReleaseYear(song.getReleaseYear());
        song.setAlbum(album);

        songRepository.save(song);
    }
}
