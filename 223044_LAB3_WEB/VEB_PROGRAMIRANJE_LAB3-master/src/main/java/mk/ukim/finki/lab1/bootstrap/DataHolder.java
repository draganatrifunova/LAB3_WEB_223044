package mk.ukim.finki.lab1.bootstrap;

import jakarta.annotation.PostConstruct;
import mk.ukim.finki.lab1.model.Album;
import mk.ukim.finki.lab1.model.Artist;
import mk.ukim.finki.lab1.model.Song;
import mk.ukim.finki.lab1.repository.AlbumRepository;
import mk.ukim.finki.lab1.repository.ArtistRepository;
import mk.ukim.finki.lab1.repository.SongRepository;
import org.springframework.stereotype.Component;

@Component
public class DataHolder {

    private final AlbumRepository albumRepository;
    private final ArtistRepository artistRepository;
    private final SongRepository songRepository;

    public DataHolder(AlbumRepository albumRepository, ArtistRepository artistRepository, SongRepository songRepository) {
        this.albumRepository = albumRepository;
        this.artistRepository = artistRepository;
        this.songRepository = songRepository;
    }

    @PostConstruct
    public void init() {
        Album album1 = new Album("Album1", "Rock", "2020");
        Album album2 = new Album("Album2", "Pop", "2012");
        Album album3 = new Album("Album3", "Hip-hop", "2008");
        Album album4 = new Album("Album4", "Rap", "1991");
        Album album5 = new Album("Album5", "Pop", "2010");

        albumRepository.save(album1);
        albumRepository.save(album2);
        albumRepository.save(album3);
        albumRepository.save(album4);
        albumRepository.save(album5);

        artistRepository.save(new Artist("Tose", "Proevski", "Makedonski peac"));
        artistRepository.save(new Artist("Esma", "Redzepova", "Romska peacka"));
        artistRepository.save(new Artist("Taylor", "Swift", "Amerikanska peacka"));
        artistRepository.save(new Artist("Mustafa'", "Ceceli", "Turski peac"));
        artistRepository.save(new Artist("Sasa", "Matic", "Srpski peac"));

        songRepository.save(new Song("Song One", "Rock", 2005, album1));
        songRepository.save(new Song("Song Two", "Pop", 2006, album2));
        songRepository.save(new Song("Song Three", "Hip-hop", 2007, album3));
        songRepository.save(new Song("Song Four", "Rap", 2008, album4));
        songRepository.save(new Song("Song Five", "Pop", 2009, album5));
    }
}
