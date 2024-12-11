package mk.ukim.finki.lab1.service.impl;

import mk.ukim.finki.lab1.model.Artist;
import mk.ukim.finki.lab1.repository.ArtistRepository;
import mk.ukim.finki.lab1.service.ArtistService;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@Primary
public class ArtistServiceImpl implements ArtistService {
    private final ArtistRepository artistRepository;

    public ArtistServiceImpl(ArtistRepository artistRepository) {
        this.artistRepository = artistRepository;
    }

    @Override
    public List<Artist> listArtists() {
       return artistRepository.findAll();
    }

    @Override
    public Artist ArtistfindById(Long id) {
        return artistRepository.findById(id).get();
    }
}
