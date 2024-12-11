package mk.ukim.finki.lab1.service.impl;

import mk.ukim.finki.lab1.model.Album;
import mk.ukim.finki.lab1.repository.AlbumRepository;
import mk.ukim.finki.lab1.service.AlbumService;
import org.springframework.stereotype.Service;

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
}
