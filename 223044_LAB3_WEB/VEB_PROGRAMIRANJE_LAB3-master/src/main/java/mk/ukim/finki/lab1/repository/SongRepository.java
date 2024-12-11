package mk.ukim.finki.lab1.repository;

import mk.ukim.finki.lab1.bootstrap.DataHolder;
import mk.ukim.finki.lab1.model.Album;
import mk.ukim.finki.lab1.model.Artist;
import mk.ukim.finki.lab1.model.Song;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

@Repository
public interface SongRepository extends JpaRepository<Song, Long> {

    List<Song> findByAlbumId(Long albumId);

}
