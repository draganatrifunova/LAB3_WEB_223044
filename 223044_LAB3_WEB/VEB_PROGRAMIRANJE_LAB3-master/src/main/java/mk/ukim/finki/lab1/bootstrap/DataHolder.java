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
        Album afterHours = new Album("After Hours", "R&B", "2020");
        Album bornToDie = new Album("Born to Die", "Alternative", "2012");
        Album fearless = new Album("Fearless", "Country pop", "2008");
        Album useYourIllusionI = new Album("Use Your Illusion I", "Rock", "1991");
        Album dooWopsHooligans = new Album("Doo-Wops & Hooligans", "R&B/Soul", "2010");

        albumRepository.save(afterHours);
        albumRepository.save(bornToDie);
        albumRepository.save(fearless);
        albumRepository.save(useYourIllusionI);
        albumRepository.save(dooWopsHooligans);

        artistRepository.save(new Artist("The", "Weeknd", "text1"));
        artistRepository.save(new Artist("Lana", "Del Ray", "text2"));
        artistRepository.save(new Artist("Taylor", "Swift", "text3"));
        artistRepository.save(new Artist("Guns N'", "Roses", "text4"));
        artistRepository.save(new Artist("Bruno", "Mars", "text5"));

        songRepository.save(new Song("After Hours", "R&B", 2020, afterHours));
        songRepository.save(new Song("Summertime Sadness", "Alternative", 2012, bornToDie));
        songRepository.save(new Song("Love Story", "Country pop", 2008, fearless));
        songRepository.save(new Song("November Rain", "Rock", 1991, useYourIllusionI));
        songRepository.save(new Song("Grenade", "R&B/Soul", 2010, dooWopsHooligans));
    }
}
